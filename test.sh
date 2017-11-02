#! /usr/bin/sudo /bin/bash
PWD=$(pwd)
cd $PWD/tests
./build
cd -
RUST_BACKTRACE=1 $HOME/.cargo/bin/cargo test $@ -- --nocapture
