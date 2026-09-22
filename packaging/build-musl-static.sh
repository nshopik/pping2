#!/bin/sh
# Build static libtins (cached in .libtins-static) and a static musl pping2.
# Runs inside alpine:3.20 with the repo mounted at /work. Needs
# LIBTINS_VERSION, HOST_UID and HOST_GID in the environment.
set -eux
apk add --no-cache build-base cmake git pkgconf \
    libpcap-dev linux-headers binutils file

if [ ! -f .libtins-static/lib/libtins.a ]; then
    rm -rf .libtins-static
    git clone --depth=1 --branch "$LIBTINS_VERSION" \
        https://github.com/mfontanini/libtins.git /tmp/libtins-src
    cmake -S /tmp/libtins-src -B /tmp/libtins-build \
        -DCMAKE_BUILD_TYPE=Release \
        -DLIBTINS_BUILD_SHARED=0 \
        -DLIBTINS_ENABLE_PCAP=1 \
        -DCMAKE_INSTALL_PREFIX=/work/.libtins-static
    cmake --build /tmp/libtins-build --parallel "$(nproc)"
    cmake --install /tmp/libtins-build
fi

make STATIC=1 LIBTINS=/work/.libtins-static

# PT_INTERP or a NEEDED entry means the build fell back to dynamic linking.
file pping2
if readelf -l pping2 | grep -q INTERP; then
    echo "FAIL: binary has dynamic interpreter"
    readelf -l pping2 | grep -A1 INTERP
    exit 1
fi
if readelf -d pping2 | grep -q NEEDED; then
    echo "FAIL: binary has NEEDED entries"
    readelf -d pping2 | grep NEEDED
    exit 1
fi
echo "OK: fully static, no shared library deps"

./pping2 -h >/dev/null 2>&1

# Return ownership to the runner uid so cache save and upload can read /work.
chown -R "$HOST_UID":"$HOST_GID" /work
