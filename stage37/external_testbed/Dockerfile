FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG OPEN5GS_REF=v2.7.6

RUN apt-get update && apt-get install -y --no-install-recommends     ca-certificates git meson ninja-build build-essential flex bison cmake     python3 python3-pip python3-setuptools python3-wheel pkg-config     libsctp-dev libc-ares-dev libgnutls28-dev libgcrypt-dev libssl-dev     libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev     libcurl4-gnutls-dev libtins-dev libtalloc-dev libidn-dev     && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --branch "${OPEN5GS_REF}" --depth 1 https://github.com/open5gs/open5gs.git

COPY live/stage37-nnrf-handler.c /tmp/stage37-nnrf-handler.c

WORKDIR /src/open5gs
RUN mkdir -p /var/log/open5gs /run/stage37     && test "$(git describe --tags --exact-match)" = "v2.7.6"     && cp /tmp/stage37-nnrf-handler.c src/nrf/nnrf-handler.c     && meson setup build     && ninja -C build         src/nrf/open5gs-nrfd         src/scp/open5gs-scpd         src/nssf/open5gs-nssfd

RUN python3 -m pip install --break-system-packages --no-cache-dir h2 cryptography

RUN mkdir -p /opt/stage37
COPY stage34/external_testbed/nrf.yaml /opt/stage37/nrf.yaml
COPY stage34/external_testbed/scp.yaml /opt/stage37/scp.yaml
COPY stage34/external_testbed/nssf1.yaml /opt/stage37/nssf1.yaml
COPY stage34/external_testbed/nssf2.yaml /opt/stage37/nssf2.yaml
COPY stage34/external_testbed/collector_service.py /opt/stage37/stage34_collector_service.py
COPY live/stage37-nnrf-handler.c /opt/stage37/stage37-nnrf-handler.c
COPY stage37/external_testbed/collector_service.py /opt/stage37/collector_service.py

WORKDIR /opt/stage37
CMD ["python3", "/opt/stage37/collector_service.py"]
