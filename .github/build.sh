#!/bin/sh

# CI script to build for "ubuntu", "mingw-32", "mingw-64", "macos", "coverity"

set -ex -o xtrace

DEPS="gengetopt help2man automake libtool"

case "$1" in
    mingw-32)
        DEPS="$DEPS mingw-w64-tools binutils-mingw-w64-i686 gcc-mingw-w64-i686"
        ;;
    mingw-64)
        DEPS="$DEPS mingw-w64-tools binutils-mingw-w64-x86-64 gcc-mingw-w64-x86-64"
        ;;
    ubuntu|coverity)
        DEPS="$DEPS gccgo golang-go openjdk-8-jdk openjdk-8-jre-headless python-dev ruby-dev swig xutils-dev doxygen"
        ;;
esac

if [ "$1" == "macos" ]; then
    brew install $DEPS
else
    sudo apt-get install -y $DEPS
fi

if [ "$1" == "ubuntu" ]; then
    # full documentation is only built on ubuntu
    pip install -U sphinx sphinx-bootstrap-theme breathe sphinxcontrib-programoutput
fi

autoreconf -vis

case "$1" in
    mingw-32|mingw-64|macos)
        ./configure --enable-openssl-install
        ;;
    ubuntu|coverity)
        export GCCGOFLAGS="-static-libgcc $CFLAGS"
        ./configure --enable-python --enable-java --enable-ruby --enable-go
        ;;
esac

case "$1" in
    ubuntu)
        make
        make check
        sudo make install
        make distcheck
        sudo make uninstall
        ;;
    mingw-32)
        make win WIN_TOOL=i686-w64-mingw32
        ;;
    mingw-64)
        make win WIN_TOOL=x86_64-w64-mingw32
        ;;
    macos)
        make osx
        ;;
esac
