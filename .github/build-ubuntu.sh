#!/bin/sh

set -ex -o xtrace

sudo apt-get install -y gccgo gengetopt golang-go help2man openjdk-8-jdk openjdk-8-jre-headless python-dev ruby-dev swig xutils-dev doxygen
pip install -U sphinx sphinx-bootstrap-theme breathe sphinxcontrib-programoutput
autoreconf -vis

export GCCGOFLAGS="-static-libgcc $CFLAGS"
./configure --enable-python --enable-java --enable-ruby --enable-go

make
make check

sudo make install

make distcheck
