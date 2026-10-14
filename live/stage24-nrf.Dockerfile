FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG OPEN5GS_REF=v2.7.6

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git meson ninja-build build-essential flex bison cmake \
    python3-pip python3-setuptools python3-wheel pkg-config \
    libsctp-dev libc-ares-dev libgnutls28-dev libgcrypt-dev libssl-dev \
    libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev \
    libcurl4-gnutls-dev libtins-dev libtalloc-dev libidn-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --branch "${OPEN5GS_REF}" --depth 1 https://github.com/open5gs/open5gs.git

COPY live/stage24-nnrf-handler.c /tmp/stage24-nnrf-handler.c

WORKDIR /src/open5gs
RUN mkdir -p /var/log/open5gs /run/stage24 \
    && test "$(git describe --tags --exact-match)" = "v2.7.6" \
    && cp /tmp/stage24-nnrf-handler.c src/nrf/nnrf-handler.c \
    && meson setup build \
    && ninja -C build src/nrf/open5gs-nrfd

LABEL org.opencontainers.image.source="https://github.com/open5gs/open5gs"
LABEL org.opencontainers.image.version="v2.7.6"
LABEL stage24.research.instrumentation="native-nrf-inprocess-discovery-response"
LABEL stage24.remote-control-surface="none"

ENTRYPOINT ["/src/open5gs/build/src/nrf/open5gs-nrfd"]
