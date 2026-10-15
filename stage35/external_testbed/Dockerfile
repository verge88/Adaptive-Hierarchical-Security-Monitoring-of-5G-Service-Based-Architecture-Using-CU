FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG OPEN5GS_REF=v2.7.6

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git meson ninja-build build-essential flex bison cmake \
    python3 python3-pip python3-setuptools python3-wheel pkg-config \
    libsctp-dev libc-ares-dev libgnutls28-dev libgcrypt-dev libssl-dev \
    libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev \
    libcurl4-gnutls-dev libtins-dev libtalloc-dev libidn-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --branch "${OPEN5GS_REF}" --depth 1 https://github.com/open5gs/open5gs.git

COPY live/stage34-nnrf-handler.c /tmp/stage34-nnrf-handler.c

WORKDIR /src/open5gs
RUN mkdir -p /var/log/open5gs /run/stage34 \
    && test "$(git describe --tags --exact-match)" = "v2.7.6" \
    && cp /tmp/stage34-nnrf-handler.c src/nrf/nnrf-handler.c \
    && meson setup build \
    && ninja -C build \
        src/nrf/open5gs-nrfd \
        src/scp/open5gs-scpd \
        src/nssf/open5gs-nssfd

RUN python3 -m pip install --break-system-packages --no-cache-dir h2 cryptography

RUN mkdir -p /opt/stage34 /opt/stage35
COPY stage34/external_testbed/nrf.yaml /opt/stage34/nrf.yaml
COPY stage34/external_testbed/scp.yaml /opt/stage34/scp.yaml
COPY stage34/external_testbed/nssf1.yaml /opt/stage34/nssf1.yaml
COPY stage34/external_testbed/nssf2.yaml /opt/stage34/nssf2.yaml
COPY stage34/external_testbed/collector_service.py /opt/stage35/stage34_collector_service.py
COPY live/stage34-nnrf-handler.c /opt/stage35/stage34-nnrf-handler.c
COPY stage35/external_testbed/collector_service.py /opt/stage35/collector_service.py

WORKDIR /opt/stage35
CMD ["python3", "/opt/stage35/collector_service.py"]
