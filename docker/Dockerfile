# One image for both roles. BelNet only ships x86_64 Linux builds, hence amd64.
# The Go binary is cross-compiled on the host (Go under qemu is unreliable):
#   GOWORK=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o docker/belnet-bridge .
FROM --platform=linux/amd64 debian:bookworm-slim
ARG BELNET_VERSION=v0.9.8
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iptables openssl ca-certificates curl tcpdump xz-utils procps dnsutils \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/Beldex-Coin/belnet/releases/download/${BELNET_VERSION}/belnet-linux-x86_64-${BELNET_VERSION}.tar.xz \
      | tar -xJ -C /usr/local/bin --strip-components=1
COPY docker/belnet-bridge docker/*-entrypoint.sh /usr/local/bin/
