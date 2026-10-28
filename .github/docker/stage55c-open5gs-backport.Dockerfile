FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG OPEN5GS_REF=v2.7.6
ARG BODY_LIFETIME_FIX=cd1cbc3233ed93d2b5f1e47fd4611f569b282af9
ARG FRAME_CHUNK_FIX=e2e3e55a0ec11c2efd98fb5aa25008fa2b1d8e97

RUN apt-get update && apt-get install -y --no-install-recommends     ca-certificates git meson ninja-build build-essential flex bison cmake openssl     python3 python3-pip python3-setuptools python3-wheel pkg-config     libsctp-dev libc-ares-dev libgnutls28-dev libgcrypt-dev libssl-dev     libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev     libcurl4-gnutls-dev libtins-dev libtalloc-dev libidn-dev     && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --branch "${OPEN5GS_REF}" --depth 1 https://github.com/open5gs/open5gs.git

COPY stage38/patch_sbi_context.py /tmp/patch_sbi_context.py

WORKDIR /src/open5gs
RUN test "$(git describe --tags --exact-match)" = "v2.7.6"     && git fetch --depth=2 origin "${BODY_LIFETIME_FIX}"     && git show --format= "${BODY_LIFETIME_FIX}" -- lib/sbi/nghttp2-server.c > /tmp/body-lifetime.patch     && git apply --check /tmp/body-lifetime.patch     && git apply /tmp/body-lifetime.patch     && git fetch --depth=2 origin "${FRAME_CHUNK_FIX}"     && git show --format= "${FRAME_CHUNK_FIX}" -- lib/sbi/nghttp2-server.c > /tmp/frame-chunk.patch     && git apply --check /tmp/frame-chunk.patch     && git apply /tmp/frame-chunk.patch     && git diff --check     && python3 /tmp/patch_sbi_context.py     && mkdir -p /var/log/open5gs /run/stage54/witness     && printf 'base=%s\nbody_lifetime_fix=%s\nframe_chunk_fix=%s\n'        "${OPEN5GS_REF}" "${BODY_LIFETIME_FIX}" "${FRAME_CHUNK_FIX}"        > /opt/stage55c_backport.txt     && meson setup build     && ninja -C build         src/nrf/open5gs-nrfd         src/nssf/open5gs-nssfd

RUN python3 -m pip install --break-system-packages --no-cache-dir h2

WORKDIR /opt/stage55
CMD ["python3","/opt/stage55.py","--count","4000","--worker","0","--hold-seconds","30","--converge-timeout","1800","--output","/out"]
