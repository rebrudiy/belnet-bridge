#!/usr/bin/env bash
set -euo pipefail

case "${BB_SOURCE_VARIANT:?}" in
  unmodified) expected_handler=a4f29b7d18a9a4141bea9f4c52a7b2b5e1bb337aeb067caeced145c839359642 ;;
  queuefix) expected_handler=a9b3fe870e7103ecbbb3c7ad8dbadb075d8fcccd1ae483490b6e3afa840c955b ;;
  *) echo 'Invalid source variant' >&2; exit 2 ;;
esac
echo "$expected_handler  /src/llarp/router/outbound_message_handler.cpp" | sha256sum --check
test "$(git -C /src rev-parse HEAD)" = 480aafb3c68ac359f0711b2cbd8a07be661703c0

cmake -S /src -B /out/cmake -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DTESTNET=ON -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_DEPS=OFF \
  -DBUILD_GUI=OFF -DBUILD_LIBBELNET=OFF -DWITH_BOOTSTRAP=OFF \
  -DWITH_TESTS=OFF -DWITH_HIVE=OFF -DWITH_LTO=OFF \
  -DWITH_SYSTEMD=OFF -DWITH_SETCAP=OFF -DUSE_JEMALLOC=OFF \
  -DNATIVE_BUILD=OFF -DOXEN_LOGGING_FORCE_SUBMODULES=ON

# Do this BEFORE the first compilation. Source remains read-only.
cp /out/cmake/build.ninja /out/build.ninja.before-endpoint-override
awk -f /recipe/endpoint-flags.awk /out/cmake/build.ninja > /out/cmake/build.ninja.override
mv /out/cmake/build.ninja.override /out/cmake/build.ninja
diff -u /out/build.ninja.before-endpoint-override /out/cmake/build.ninja > /out/endpoint-optimization.diff || test "$?" = 1
ninja -C /out/cmake -j1 belnet

mkdir -p /out/bin /out/lib
cp /out/cmake/daemon/belnet /out/bin/belnet
find /out/cmake/external \( -type f -o -type l \) -name '*.so*' -exec cp -a {} /out/lib/ \;
sha256sum /out/bin/belnet /out/bin/belnet-bridge > /out/binary-sha256.txt
/out/bin/belnet --version > /out/belnet.version 2>&1
ldd /out/bin/belnet > /out/belnet.ldd
git -C /src diff -- llarp/router/outbound_message_handler.cpp > /out/effective-handler.diff
dpkg-query -W > /out/build-packages.tsv
cmake --version > /out/cmake.version
c++ --version > /out/compiler.version
