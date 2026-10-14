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

COPY live/stage23-sbi-path.c /tmp/stage23-sbi-path.c

WORKDIR /src/open5gs
RUN test "$(git describe --tags --exact-match)" = "v2.7.6" \
    && cp /tmp/stage23-sbi-path.c src/scp/sbi-path.c \
    && meson setup build --prefix=/opt/open5gs \
    && ninja -C build open5gs-scpd \
    && ninja -C build install

LABEL org.opencontainers.image.source="https://github.com/open5gs/open5gs"
LABEL org.opencontainers.image.version="v2.7.6"
LABEL stage23.research.instrumentation="native-scp-inprocess-response"
LABEL stage23.remote-control-surface="none"

ENV PATH="/opt/open5gs/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/open5gs/lib/x86_64-linux-gnu:/opt/open5gs/lib:${LD_LIBRARY_PATH}"
ENV STAGE23_LAB_TAMPER=1

ENTRYPOINT ["/opt/open5gs/bin/open5gs-scpd"]
