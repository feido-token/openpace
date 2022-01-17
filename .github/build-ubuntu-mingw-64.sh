#!/bin/sh

set -ex -o xtrace

sudo apt-get install -y gengetopt help2man mingw-w64-tools binutils-mingw-w64-x86-64 gcc-mingw-w64-x86-64
autoreconf -vis

./configure --enable-openssl-install

make win WIN_TOOL=x86_64-w64-mingw32
