FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config git ca-certificates \
    libsodium-dev libuv1-dev libunbound-dev libzmq3-dev libsqlite3-dev \
    libssl-dev libcap-dev libcurl4-openssl-dev libevent-dev nettle-dev \
    iproute2 iptables openssl curl tcpdump dnsutils xz-utils procps \
    && rm -rf /var/lib/apt/lists/*
RUN git config --global --add safe.directory '*'
WORKDIR /build
