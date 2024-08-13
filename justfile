# recipe to build all wit-* packages
# if it's in the crates/ or examples/ directory, build it
build-wits:
 for dir in crates/*; do \
   if [ -d $dir/wit ]; then \
     cargo component build --manifest-path=$dir/Cargo.toml; \
     cargo component build --manifest-path=$dir/Cargo.toml --release; \
   fi \
 done
 for dir in examples/*; do \
   if [ -d $dir/wit ]; then \
     cargo component build --manifest-path=$dir/Cargo.toml; \
     cargo component build --manifest-path=$dir/Cargo.toml --release; \
   fi \
 done
