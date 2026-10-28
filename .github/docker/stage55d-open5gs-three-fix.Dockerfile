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
COPY .github/docker/patch_stage55c_v276_h2_response.py /tmp/patch_stage55c_v276_h2_response.py
COPY .github/docker/patch_stage55d_v276_defer_send.py /tmp/patch_stage55d_v276_defer_send.py

WORKDIR /src/open5gs
RUN test "$(git describe --tags --exact-match)" = "v2.7.6" \
    && python3 /tmp/patch_stage55c_v276_h2_response.py \
    && python3 /tmp/patch_stage55d_v276_defer_send.py \
    && git diff --check \
    && python3 /tmp/patch_sbi_context.py \
    && mkdir -p /var/log/open5gs /run/stage54/witness \
    && printf 'base=%s\nbody_lifetime_fix=%s\nframe_chunk_fix=%s\ndefer_send_fix=%s\nadaptation=%s\n' \
       "${OPEN5GS_REF}" \
       "cd1cbc3233ed93d2b5f1e47fd4611f569b282af9" \
       "e2e3e55a0ec11c2efd98fb5aa25008fa2b1d8e97" \
       "d6f1ed86b7c6abea8b15fc8a007016210afd6a23" \
       "v2.7.6-contextual-three-fix-backport" \
       > /opt/stage55d_backport.txt \
    && meson setup build \
    && ninja -C build \
        src/nrf/open5gs-nrfd \
        src/nssf/open5gs-nssfd

RUN python3 -m pip install --break-system-packages --no-cache-dir h2

WORKDIR /opt/stage55
CMD ["python3","/opt/stage55d.py","--count","100","--worker","0","--hold-seconds","5","--converge-timeout","300","--output","/out"]
