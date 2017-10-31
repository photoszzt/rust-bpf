#! /usr/bin/sudo /bin/bash
PWD=$(pwd)
cd $PWD/tests
./build
cd -
$HOME/.cargo/bin/cargo test
