#!/bin/sh

set -ex -o xtrace

brew install gengetopt help2man automake libtool
autoreconf -vis

./configure --enable-openssl-install

make osx
