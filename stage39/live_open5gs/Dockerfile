FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG OPEN5GS_REF=v2.7.6

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git meson ninja-build build-essential flex bison cmake openssl \
    python3 python3-pip python3-setuptools python3-wheel pkg-config \
    libsctp-dev libc-ares-dev libgnutls28-dev libgcrypt-dev libssl-dev \
    libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev \
    libcurl4-gnutls-dev libtins-dev libtalloc-dev libidn-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --branch "${OPEN5GS_REF}" --depth 1 https://github.com/open5gs/open5gs.git

COPY stage39/live_open5gs/stage39-nnrf-handler.c /tmp/stage39-nnrf-handler.c
COPY stage38/patch_sbi_context.py /tmp/patch_sbi_context.py

WORKDIR /src/open5gs
RUN mkdir -p /var/log/open5gs /run/stage39/witness /run/stage38 \
    && test "$(git describe --tags --exact-match)" = "v2.7.6" \
    && cp /tmp/stage39-nnrf-handler.c src/nrf/nnrf-handler.c \
    && python3 /tmp/patch_sbi_context.py \
    && meson setup build \
    && ninja -C build \
        src/nrf/open5gs-nrfd \
        src/scp/open5gs-scpd \
        src/nssf/open5gs-nssfd \
        src/ausf/open5gs-ausfd \
        src/bsf/open5gs-bsfd \
        src/udm/open5gs-udmd \
        src/amf/open5gs-amfd \
        src/smf/open5gs-smfd \
        src/pcf/open5gs-pcfd

RUN python3 -m pip install --break-system-packages --no-cache-dir h2 cryptography

RUN mkdir -p /opt/stage39/hnet /opt/stage38/hnet \
    && openssl genpkey -algorithm X25519 -out /opt/stage38/hnet/curve25519-1.key \
    && cp /opt/stage38/hnet/curve25519-1.key /opt/stage39/hnet/curve25519-1.key \
    && chmod 600 /opt/stage38/hnet/curve25519-1.key /opt/stage39/hnet/curve25519-1.key

COPY stage38/external_testbed/*.yaml /opt/stage39/
COPY stage39/live_open5gs/*.yaml /opt/stage39/
COPY research/stage39_kie.py /opt/stage39/stage39_kie.py
COPY stage39/live_open5gs/live_probe.py /opt/stage39/live_probe.py
COPY stage39/full_profile_policy.json /opt/stage39/full_profile_policy.json
COPY stage39/live_open5gs/live_policy.json /opt/stage39/live_policy.json

WORKDIR /opt/stage39
CMD ["python3", "/opt/stage39/live_probe.py", "--output", "/out"]
