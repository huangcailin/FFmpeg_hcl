#!/bin/bash

git reset --hard
git clean -dfx
git pull --rebase
git log -1

export CFLAGS="-fstack-protector-all -Wl,-z,now -s"
export PKG_CONFIG_PATH=/home/opensource/openh264/install/lib/pkgconfig
./configure --prefix="./ffmpeg_build"  --enable-shared --disable-iconv --disable-ffplay --disable-bsfs --disable-ffprobe --enable-libopenh264 --disable-ffmpeg --disable-ffplay --disable-ffprobe --disable-muxers --disable-outdevs  --disable-static --disable-bzlib --disable-zlib --disable-indevs  --disable-encoders --disable-filters --extra-ldflags=-L./../openh264/install/lib --extra-cflags="-I./../openh264/install/include -fPIE -pie -s -fstack-protector-all -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"  --extra-cxxflags=" -fPIE -pie -s -fstack-protector-all -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack" --ld="gcc -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack" --enable-openssl --enable-protocols --enable-protocol=https
make & make install