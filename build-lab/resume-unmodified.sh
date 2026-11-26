#!/usr/bin/env bash
set -euo pipefail

# Do not reconfigure CMake here: the recorded endpoint.cpp -O0 rule is intentional.
echo 'a4f29b7d18a9a4141bea9f4c52a7b2b5e1bb337aeb067caeced145c839359642  /src/llarp/router/outbound_message_handler.cpp' | sha256sum --check
# Switching back from the optional overlay must invalidate its cached object.
rm -f /out/cmake/llarp/CMakeFiles/belnet-amalgum.dir/router/outbound_message_handler.cpp.o
ninja -C /out/cmake -j1 belnet
mkdir -p /out/bin
cp /out/cmake/daemon/belnet /out/bin/belnet
cp /out/bin/belnet /out/bin/belnet.unmodified
sha256sum /out/bin/belnet > /out/belnet.sha256
sha256sum /out/bin/belnet.unmodified > /out/belnet.unmodified.sha256
/out/bin/belnet --version > /out/belnet.version 2>&1
ldd /out/bin/belnet > /out/belnet.ldd
git -C /src rev-parse HEAD > /out/source.commit
git -C /src submodule status --recursive > /out/source.submodules
dpkg-query -W > /out/build-packages.tsv
cmake --version > /out/cmake.version
c++ --version > /out/compiler.version
