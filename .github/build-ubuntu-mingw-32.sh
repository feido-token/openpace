#!/bin/sh

set -ex -o xtrace

sudo apt-get install -y gengetopt help2man mingw-w64-tools binutils-mingw-w64-i686 gcc-mingw-w64-i686
autoreconf -vis

./configure --enable-openssl-install

make win WIN_TOOL=i686-w64-mingw32
