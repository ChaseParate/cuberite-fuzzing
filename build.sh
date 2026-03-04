#!/bin/bash

cd cuberite

if [ ! -f build ]; then
    mkdir build
fi

cd build
cmake .. -DCMAKE_C_COMPILER=afl-clang-lto -DCMAKE_CXX_COMPILER=afl-clang-lto++
make -j
