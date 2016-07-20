#!/bin/bash

rm -rf libs

ndk-build clean
ndk-build

desPath="../assets/armeabi-v7a"
mkdir -p $desPath

cp -f libs/armeabi-v7a/* $desPath/


