#!/usr/bin/env bash
set -euo pipefail

# The caller mounts only the patched handler as a read-only source overlay.
echo 'a9b3fe870e7103ecbbb3c7ad8dbadb075d8fcccd1ae483490b6e3afa840c955b  /src/llarp/router/outbound_message_handler.cpp' | sha256sum --check
# Force this object to rebuild even if the overlay timestamp predates the cache.
rm -f /out/cmake/llarp/CMakeFiles/belnet-amalgum.dir/router/outbound_message_handler.cpp.o
ninja -C /out/cmake -j1 belnet
cp /out/cmake/daemon/belnet /out/bin/belnet.queuefix
sha256sum /out/bin/belnet.queuefix > /out/belnet.queuefix.sha256
/out/bin/belnet.queuefix --version > /out/belnet.queuefix.version 2>&1
ldd /out/bin/belnet.queuefix > /out/belnet.queuefix.ldd
