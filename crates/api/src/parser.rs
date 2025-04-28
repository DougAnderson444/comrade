//! Our pest parsed struct. This is where the Abstact syntax tree will land once the grammar is
//! applied.
//! For our scripts, we have a very simple language witht he same rules as Rust.
//! The scripts are essentially just a list of function calls, with the first function being the entry point.
//! Functions are separated by either a newline or a logical operator (|| for or, && for and).
//! Then each function in the script is mapped to the function in the API.
//!
//! For example, the following script:
//!
//! ```
//! check_signature("/tpubkey", "/entry/") ||
//! // then check a possible pubkey sig...
//! check_signature("/pubkey", "/entry/") ||
//! // then the pre-image proof...
//! check_preimage("/hash")
//! ```
//!
//! Would be parsed intot the AST, the executed int he same order, calling the same named functions
//! in Rust, until "true" is returned.
//!
//! ## List of all possible functions:
//! - `check_eq(key: String)`
//! - `check_signature(key: String, msg: String)`
//! - `check_preimage(preimage: String)`
//! - `check_hash(hash: String)`
//! - `push(path: String)`
//! - `branch(branch: String) -> String`
//!
//! `branch()` is the only Rust function that returns a String instead of bool.
//!
//! The order must be preserved such that the order of operations is the same as the order of the
//! script.
//!
//! Recursion can be used as functions in the cript can be nested:
//!
//! ## Nested example:
//! ```
//! // forking the parent be done by whomever can sign with "/forks/pubkey"
//! check_signature(branch("pubkey")) ||
//!
//! // check the validity of the first entry of the child plog
//! (check_eq(branch("vlad")) && check_signature(branch("pubkey")))
//! ````

// allow unused
#![allow(unused)]

use pest::Parser;
use pest::iterators::{Pair, Pairs};
use pest_derive::Parser;

use crate::error::ApiError;

#[derive(Parser)]
#[grammar = "grammar.pest"]
pub struct ScriptParser;

/// Our AST defintion in Rust. Each function type is represented by an enum variant.
#[derive(Debug, Clone, PartialEq)]
pub enum Function<'a> {
    /// A function that checks the equality of a key.
    CheckEq(&'a str),
    /// A function that checks the signature of a key and message.
    CheckSignature(&'a str, &'a str),
    /// A function that checks the preimage of a key.
    CheckPreimage(&'a str),
    /// A function that checks the hash of a key.
    CheckHash(&'a str),
    /// A function that pushes a path to the stack.
    Push(&'a str),
    /// A function that branches to another path.
    Branch(&'a str),
}

/// Represents a complete expression tree
#[derive(Debug, Clone, PartialEq)]
pub enum Expression<'a> {
    Function(Function<'a>),
    And(Box<Expression<'a>>, Box<Expression<'a>>),
    Or(Box<Expression<'a>>, Box<Expression<'a>>),
    Group(Box<Expression<'a>>),
}

/// The complete script AST
#[derive(Debug, Clone, PartialEq)]
pub struct Script<'a> {
    pub expressions: Vec<Expression<'a>>,
}

impl<'a> Script<'a> {
    /// Parse a script from a string
    pub fn parse(script_str: &'a str) -> Result<Self, ApiError> {
        let pairs = ScriptParser::parse(Rule::script, script_str)
            .map_err(|e| ApiError::PestParse(Box::new(e)))?;
        let expressions = Self::parse_script(pairs)?;

        Ok(Script { expressions })
    }

    /// Parse the script from pest pairs
    fn parse_script(pairs: Pairs<Rule>) -> Result<Vec<Expression>, ApiError> {
        let mut expressions = Vec::new();

        // Find the 'script' node
        for pair in pairs {
            if pair.as_rule() == Rule::script {
                // Process each expression within the script
                for inner_pair in pair.into_inner() {
                    if inner_pair.as_rule() == Rule::expr {
                        expressions.push(Self::parse_expression(inner_pair)?);
                    }
                }
                break;
            }
        }

        Ok(expressions)
    }

    /// Parse an expression from a pest pair
    fn parse_expression(pair: Pair<Rule>) -> Result<Expression, ApiError> {
        match pair.as_rule() {
            Rule::expr => {
                let inner = pair.into_inner().next().unwrap();
                Self::parse_expression(inner)
            }
            Rule::or_expr => {
                let mut inner = pair.into_inner();
                let first = Self::parse_expression(inner.next().unwrap());

                inner.fold(first, |acc, pair| {
                    // This handles "||" operators
                    Ok(Expression::Or(
                        Box::new(acc?),
                        Box::new(Self::parse_expression(pair)?),
                    ))
                })
            }
            Rule::and_expr => {
                let mut inner = pair.into_inner();
                let first = Self::parse_expression(inner.next().unwrap());

                inner.fold(first, |acc, pair| {
                    // This handles "&&" operators
                    Ok(Expression::And(
                        Box::new(acc?),
                        Box::new(Self::parse_expression(pair)?),
                    ))
                })
            }
            Rule::primary_expr => {
                let inner = pair.into_inner().next().unwrap();
                match inner.as_rule() {
                    Rule::function_call => Ok(Self::parse_function(inner)?),
                    Rule::expr => Ok(Expression::Group(Box::new(Self::parse_expression(inner)?))),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!("Unexpected rule: {:?}", pair.as_rule()),
        }
    }

    /// Parse a function call from a pest pair
    fn parse_function(pair: Pair<Rule>) -> Result<Expression, ApiError> {
        let mut inner = pair.into_inner();
        let function_name = inner.next().unwrap().as_str();

        // Parse arguments - handle both direct arguments and nested within Rule::argument
        let args: Vec<&str> = inner
            .filter_map(|p| {
                if [Rule::string_literal, Rule::path_literal, Rule::identifier]
                    .contains(&p.as_rule())
                {
                    // Direct arguments
                    let raw_str = p.as_str();
                    let arg_str = if p.as_rule() == Rule::string_literal
                        || p.as_rule() == Rule::path_literal
                    {
                        // Strip quotes
                        &raw_str[1..raw_str.len() - 1]
                    } else {
                        raw_str
                    };
                    Some(arg_str)
                } else if p.as_rule() == Rule::function_call {
                    // Handle nested function calls
                    match Self::parse_function(p.clone()) {
                        Ok(Expression::Function(Function::Branch(arg))) => Some(arg),
                        // only branch() can be nested since it's the only one that returns a String
                        _ => {
                            let msg = format!("Unsupported nested function call: {}", p.as_str());
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .collect();

        // Create the appropriate Function based on name and arguments
        let function = match function_name {
            "check_eq" if args.len() == 1 => Function::CheckEq(args[0].clone()),
            "check_signature" if args.len() == 2 => {
                Function::CheckSignature(args[0].clone(), args[1].clone())
            }
            "check_preimage" if args.len() == 1 => Function::CheckPreimage(args[0].clone()),
            "check_hash" if args.len() == 1 => Function::CheckHash(args[0].clone()),
            "push" if args.len() == 1 => Function::Push(args[0].clone()),
            "branch" if args.len() == 1 => Function::Branch(args[0].clone()),
            _ => {
                let msg = format!(
                    "Unsupported function call: {} with {} args",
                    function_name,
                    args.len()
                );
                return Err(ApiError::ParseScript(msg));
            }
        };

        Ok(Expression::Function(function))
    }

    /// Execute the script and return the result
    pub fn run(&self) -> bool {
        // Execute each expression in sequence
        for expr in &self.expressions {
            if self.eval_expression(expr) {
                return true;
            }
        }
        false
    }

    /// Evaluate a single expression
    fn eval_expression(&self, expr: &Expression) -> bool {
        match expr {
            Expression::Function(func) => self.eval_function(func),
            Expression::And(left, right) => {
                self.eval_expression(left) && self.eval_expression(right)
            }
            Expression::Or(left, right) => {
                self.eval_expression(left) || self.eval_expression(right)
            }
            Expression::Group(inner) => self.eval_expression(inner),
        }
    }

    /// Evaluate a function call
    fn eval_function(&self, function: &Function) -> bool {
        match function {
            Function::CheckEq(key) => {
                // Dummy implementation
                *key == "/match"
            }
            Function::CheckSignature(key, _msg) => {
                // Dummy implementation
                key.contains("key")
            }
            Function::CheckPreimage(preimage) => {
                // Dummy implementation
                *preimage == "/hash"
            }
            Function::CheckHash(hash) => {
                // Dummy implementation
                hash.starts_with("/h")
            }
            Function::Push(_path) => {
                // Dummy implementation: push always succeeds
                true
            }
            Function::Branch(branch) => {
                // Dummy implementation: returns a path
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_or() {
        let simple_script = r#"check_signature("/key", "/msg") || check_preimage("/hash")"#;
        let script = Script::parse(simple_script).expect("Failed to parse simple script");
        println!("Simple AST: {:#?}", script);
    }

    #[test]
    fn test_parse_and_run_script() {
        let script_str = r#"
            // then check a possible threshold sig...
            check_signature("/recoverykey", "/entry/") ||

            // then check a possible pubkey sig...
            check_signature("/pubkey", "/entry/") ||

            // then the pre-image proof...
            check_preimage("/hash")
        "#;

        let script = Script::parse(script_str).expect("Failed to parse script");

        // Debug output to see the AST
        println!("Parsed AST: {:#?}", script);

        // Run the script
        let result = script.run();
        println!("Script execution result: {}", result);

        // Since our dummy functions will match for check_signature("/pubkey", "/entry/")
        assert!(result);
    }

    #[test]
    fn test_nested_functions() {
        let script_str = r#"
            // Nested function test
            check_signature(branch("pubkey"), "/entry/") ||
            (check_eq(branch("vlad")) && check_signature("/pubkey", "/entry/"))
        "#;

        let script = Script::parse(script_str).expect("Failed to parse script");
        println!("Nested function AST: {:#?}", script);

        // Our dummy functions should succeed
        assert!(script.run());
    }

    #[test]
    fn test_all_function_types() {
        // Test script containing all function types
        let test_script = r#"
            // Test check_eq function
            check_eq("/test/path") &&

            // Test check_signature function with two arguments
            check_signature("/pubkey/path", "/message/path") &&

            // Test check_preimage function
            check_preimage("/preimage/hash") &&

            // Test check_hash function
            check_hash("/hash/value") &&

            // Test push function
            push("/stack/path") &&

            // Test branch function
            branch("branch/path")
        "#;

        let script = Script::parse(test_script).expect("Failed to parse test script");

        // We should have a single expression (all joined with AND)
        assert_eq!(script.expressions.len(), 1);

        // Extract the expression tree by recursively unwrapping the AND expressions
        fn extract_functions<'a>(expr: &'a Expression<'a>) -> Vec<&'a Function<'a>> {
            match expr {
                Expression::Function(f) => vec![f],
                Expression::And(left, right) => {
                    let mut left_funcs = extract_functions(left);
                    let mut right_funcs = extract_functions(right);
                    left_funcs.append(&mut right_funcs);
                    left_funcs
                }
                Expression::Or(left, right) => {
                    let mut left_funcs = extract_functions(left);
                    let mut right_funcs = extract_functions(right);
                    left_funcs.append(&mut right_funcs);
                    left_funcs
                }
                Expression::Group(inner) => extract_functions(inner),
            }
        }

        let functions = extract_functions(&script.expressions[0]);

        // We should have 6 functions (one of each type)
        assert_eq!(functions.len(), 6);

        // Verify each function type exists and has the correct arguments
        let has_check_eq = functions
            .iter()
            .any(|f| matches!(f, Function::CheckEq(path) if path == &"/test/path"));
        assert!(
            has_check_eq,
            "check_eq function not found or has incorrect arguments"
        );

        let has_check_signature = functions.iter().any(|f| {
            matches!(f, Function::CheckSignature(key, msg) if key == &"/pubkey/path" && msg == &"/message/path")
        });
        assert!(
            has_check_signature,
            "check_signature function not found or has incorrect arguments"
        );

        let has_check_preimage = functions.iter().any(
            |f| matches!(f, Function::CheckPreimage(preimage) if preimage == &"/preimage/hash"),
        );
        assert!(
            has_check_preimage,
            "check_preimage function not found or has incorrect arguments"
        );

        let has_check_hash = functions
            .iter()
            .any(|f| matches!(f, Function::CheckHash(hash) if hash == &"/hash/value"));
        assert!(
            has_check_hash,
            "check_hash function not found or has incorrect arguments"
        );

        let has_push = functions
            .iter()
            .any(|f| matches!(f, Function::Push(path) if path == &"/stack/path"));
        assert!(
            has_push,
            "push function not found or has incorrect arguments"
        );

        let has_branch = functions
            .iter()
            .any(|f| matches!(f, Function::Branch(branch) if branch == &"branch/path"));
        assert!(
            has_branch,
            "branch function not found or has incorrect arguments"
        );
    }

    #[test]
    fn test_individual_function_parsing() {
        // Test each function type individually to ensure proper parsing
        let check_eq_script = r#"check_eq("/test/equality")"#;
        let script = Script::parse(check_eq_script).expect("Failed to parse check_eq script");
        if let Expression::Function(Function::CheckEq(key)) = &script.expressions[0] {
            assert_eq!(*key, "/test/equality");
        } else {
            panic!("Failed to parse check_eq function");
        }

        let check_sig_script = r#"check_signature("/key/path", "/msg/data")"#;
        let script =
            Script::parse(check_sig_script).expect("Failed to parse check_signature script");
        if let Expression::Function(Function::CheckSignature(key, msg)) = &script.expressions[0] {
            assert_eq!(*key, "/key/path");
            assert_eq!(*msg, "/msg/data");
        } else {
            panic!("Failed to parse check_signature function");
        }

        let check_preimage_script = r#"check_preimage("/preimage/value")"#;
        let script =
            Script::parse(check_preimage_script).expect("Failed to parse check_preimage script");
        if let Expression::Function(Function::CheckPreimage(preimage)) = &script.expressions[0] {
            assert_eq!(*preimage, "/preimage/value");
        } else {
            panic!("Failed to parse check_preimage function");
        }

        let check_hash_script = r#"check_hash("/hash/data")"#;
        let script = Script::parse(check_hash_script).expect("Failed to parse check_hash script");
        if let Expression::Function(Function::CheckHash(hash)) = &script.expressions[0] {
            assert_eq!(*hash, "/hash/data");
        } else {
            panic!("Failed to parse check_hash function");
        }

        let push_script = r#"push("/stack/data")"#;
        let script = Script::parse(push_script).expect("Failed to parse push script");
        if let Expression::Function(Function::Push(path)) = &script.expressions[0] {
            assert_eq!(*path, "/stack/data");
        } else {
            panic!("Failed to parse push function");
        }

        let branch_script = r#"branch("branch/value")"#;
        let script = Script::parse(branch_script).expect("Failed to parse branch script");
        if let Expression::Function(Function::Branch(branch)) = &script.expressions[0] {
            assert_eq!(*branch, "branch/value");
        } else {
            panic!("Failed to parse branch function");
        }
    }

    #[test]
    fn test_error_handling_for_functions() {
        // Test parsing with invalid function calls

        // Wrong number of arguments
        let invalid_script = r#"check_eq("/test", "/extra")"#;
        assert!(
            Script::parse(invalid_script).is_err(),
            "Should error with too many arguments"
        );

        let invalid_script = r#"check_signature("/key")"#;
        assert!(
            Script::parse(invalid_script).is_err(),
            "Should error with too few arguments"
        );

        // Unknown function
        let invalid_script = r#"unknown_function("/test")"#;
        assert!(
            Script::parse(invalid_script).is_err(),
            "Should error with unknown function"
        );
    }
}
