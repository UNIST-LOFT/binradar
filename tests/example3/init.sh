#!/bin/bash
rm -rf val-src val-runtime
mkdir val-runtime
project_url=https://github.com/vadz/libtiff.git
commit_id=0ba5d88
git clone $project_url val-src
pushd val-src
  git checkout $commit_id
  ./autogen.sh
  ./configure 
  make CFLAGS="-static" CXXFLAGS="-static" -j 32
  cp tools/tiffcrop.c ../val-runtime
  cp tools/tiffcrop ../val-runtime
popd
cp exploit.tif val-runtime
