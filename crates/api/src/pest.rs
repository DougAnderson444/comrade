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
pub enum Function {
    /// A function that checks the equality of a key.
    CheckEq(String),
    /// A function that checks the signature of a key and message.
    CheckSignature(String, String),
    /// A function that checks the preimage of a key.
    CheckPreimage(String),
    /// A function that checks the hash of a key.
    CheckHash(String),
    /// A function that pushes a path to the stack.
    Push(String),
    /// A function that branches to another path.
    Branch(String),
}

/// Represents a complete expression tree
#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    Function(Function),
    And(Box<Expression>, Box<Expression>),
    Or(Box<Expression>, Box<Expression>),
    Group(Box<Expression>),
}

/// The complete script AST
#[derive(Debug, Clone, PartialEq)]
pub struct Script {
    pub expressions: Vec<Expression>,
}

impl Script {
    /// Parse a script from a string
    pub fn parse(script_str: &str) -> Result<Self, ApiError> {
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
        let args: Vec<String> = inner
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
                    Some(arg_str.to_string())
                } else if p.as_rule() == Rule::function_call {
                    // Handle nested function calls
                    match Self::parse_function(p.clone()) {
                        Ok(Expression::Function(Function::Branch(arg))) => Some(arg),
                        _ => Some(format!("<function call: {}>", p.as_str())),
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

    /// Parse an argument from a pest pair
    fn parse_argument(pair: Pair<Rule>) -> String {
        let inner_opt = pair.clone().into_inner().next();

        if let Some(inner) = inner_opt {
            match inner.as_rule() {
                Rule::string_literal | Rule::path_literal => {
                    let raw_str = inner.as_str();
                    // Strip quotes
                    raw_str[1..raw_str.len() - 1].to_string()
                }
                Rule::identifier => inner.as_str().to_string(),
                Rule::function_call => {
                    // Handle nested function calls
                    match Self::parse_function(inner.clone()) {
                        Ok(Expression::Function(Function::Branch(arg))) => arg,
                        _ => format!("<function call: {}>", inner.as_str()),
                    }
                }
                _ => unreachable!("Unexpected argument type: {:?}", inner.as_rule()),
            }
        } else {
            // Fallback for cases where there are no inner elements
            pair.as_str().to_string()
        }
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
                key == "/match"
            }
            Function::CheckSignature(key, _msg) => {
                // Dummy implementation
                key.contains("key")
            }
            Function::CheckPreimage(preimage) => {
                // Dummy implementation
                preimage == "/hash"
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
}
