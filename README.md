AliasJava
=========

This is a Java implementation of Alias using the BC data structures.

Setup
=====
Libraries

    mkdir libs
    ln -s <awcommonjavalib> libs/AletheiaWareCommonJava.jar
    ln -s <bcjavalib> libs/BCJava.jar
    ln -s <protolib> libs/protobuf-lite-3.0.1.jar

Protocol Buffers

    cd <path/to/Alias>
    ./build.sh --javalite_out=<path/to/AliasJava>/source/

Build
=====

    ./build.sh
