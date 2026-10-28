#!/usr/bin/env python3
from pathlib import Path

p=Path("/src/open5gs/lib/sbi/nghttp2-server.c")
s=p.read_text()

def one(old,new,label):
    global s
    n=s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected one marker, found {n}")
    s=s.replace(old,new,1)

one(
"""    struct h2_settings      settings;
    SSL*                    ssl;
} ogs_sbi_session_t;
""",
"""    struct h2_settings      settings;
    SSL*                    ssl;

    /* Backport of the essential defer-send mechanism from d6f1ed86. */
    bool                    in_recv;
} ogs_sbi_session_t;
""",
"session in_recv",
)

old="""        ogs_assert(sbi_sess->session);
        readlen = nghttp2_session_mem_recv(
                sbi_sess->session, pkbuf->data, pkbuf->len);
        if (readlen < 0) {
"""
new="""        ogs_assert(sbi_sess->session);
        sbi_sess->in_recv = true;
        readlen = nghttp2_session_mem_recv(
                sbi_sess->session, pkbuf->data, pkbuf->len);
        sbi_sess->in_recv = false;
        if (readlen < 0) {
"""
one(old,new,"recv defer guard")

needle="""static int session_send(ogs_sbi_session_t *sbi_sess)
{
#if USE_SEND_DATA_WITH_NO_COPY
"""
replacement="""static int session_send(ogs_sbi_session_t *sbi_sess)
{
#if USE_SEND_DATA_WITH_NO_COPY
"""
if needle not in s:
    raise SystemExit("session_send function marker not found")

marker="""    ogs_assert(sbi_sess);
    ogs_assert(sbi_sess->session);

#if USE_SEND_DATA_WITH_NO_COPY
"""
newmarker="""    ogs_assert(sbi_sess);
    ogs_assert(sbi_sess->session);

    /* nghttp2 permits submitting frames, but not sending, in receive callbacks. */
    if (sbi_sess->in_recv)
        return OGS_OK;

#if USE_SEND_DATA_WITH_NO_COPY
"""
# There should be only one such pair in session_send in v2.7.6.
one(marker,newmarker,"session_send defer")

p.write_text(s)
for marker in (
    "bool                    in_recv;",
    "sbi_sess->in_recv = true;",
    "sbi_sess->in_recv = false;",
    "if (sbi_sess->in_recv)\n        return OGS_OK;",
):
    if marker not in s:
        raise SystemExit(f"missing defer marker: {marker}")
print("patched essential Open5GS d6f1ed86 defer-send mechanism")
