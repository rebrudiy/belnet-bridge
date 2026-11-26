#!/usr/bin/env bash
set -euo pipefail

cmake -S /src -B /out/cmake -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DTESTNET=ON -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_DEPS=OFF \
  -DBUILD_GUI=OFF -DBUILD_LIBBELNET=OFF -DWITH_BOOTSTRAP=OFF \
  -DWITH_TESTS=OFF -DWITH_HIVE=OFF -DWITH_LTO=OFF \
  -DWITH_SYSTEMD=OFF -DWITH_SETCAP=OFF -DUSE_JEMALLOC=OFF \
  -DNATIVE_BUILD=OFF -DOXEN_LOGGING_FORCE_SUBMODULES=ON
cmake --build /out/cmake --target belnet -j 1
mkdir -p /out/bin
cp /out/cmake/daemon/belnet /out/bin/belnet
sha256sum /out/bin/belnet > /out/belnet.sha256
/out/bin/belnet --version > /out/belnet.version
ldd /out/bin/belnet > /out/belnet.ldd
git -C /src rev-parse HEAD > /out/source.commit
git -C /src submodule status --recursive > /out/source.submodules
dpkg-query -W > /out/build-packages.tsv
cmake --version > /out/cmake.version
c++ --version > /out/compiler.version
