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

COPY stage38/patch_sbi_context.py /tmp/patch_sbi_context.py

WORKDIR /src/open5gs
RUN mkdir -p /var/log/open5gs /run/stage53/witness \
    && test "$(git describe --tags --exact-match)" = "v2.7.6" \
    && python3 /tmp/patch_sbi_context.py \
    && meson setup build \
    && ninja -C build \
        src/nrf/open5gs-nrfd \
        src/scp/open5gs-scpd \
        src/nssf/open5gs-nssfd

RUN python3 -m pip install --break-system-packages --no-cache-dir h2

WORKDIR /opt/stage53
COPY stage53/stage53_scale_worker.py /opt/stage53/stage53_scale_worker.py

CMD ["python3","/opt/stage53/stage53_scale_worker.py","--count","100","--worker","0","--hold-seconds","20","--output","/out"]
