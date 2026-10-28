#!/usr/bin/env python3
from pathlib import Path

p=Path("/src/open5gs/lib/sbi/nghttp2-server.c")
s=p.read_text()

def rep(old,new,label):
    global s
    n=s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected one marker, found {n}")
    s=s.replace(old,new,1)

rep(
"""    int32_t                 stream_id;
    ogs_sbi_request_t       *request;
    bool                    memory_overflow;

    ogs_sbi_session_t       *session;
} ogs_sbi_stream_t;
""",
"""    int32_t                 stream_id;
    ogs_sbi_request_t       *request;
    bool                    memory_overflow;

    ogs_sbi_session_t       *session;

    /*
     * Backport of Open5GS cd1cbc3 + e2e3e55 for v2.7.6:
     * keep response storage alive for deferred HTTP/2 DATA and track chunks.
     */
    struct {
        void                *data;
        size_t              len;
        size_t              sent;
    } body;
    bool                    responded;
} ogs_sbi_stream_t;
""","stream body state")

rep(
"""    ogs_sbi_response_t *response = NULL;
    ogs_sbi_stream_t *stream = NULL;
""",
"""    ogs_sbi_stream_t *stream = NULL;
    size_t n;
    bool last;
""","read callback locals")

rep(
"""    ogs_assert(source);
    response = source->ptr;
    ogs_assert(response);

    ogs_assert(response->http.content);
    ogs_assert(response->http.content_length);

#if USE_SEND_DATA_WITH_NO_COPY
    *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;
#else
    memcpy(buf, response->http.content, response->http.content_length);
#endif

    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
""",
"""    ogs_assert(stream->body.data);
    ogs_assert(stream->body.len);
    ogs_assert(stream->body.sent < stream->body.len);

    n = ogs_min(length, stream->body.len - stream->body.sent);
    last = (stream->body.sent + n == stream->body.len);

#if USE_SEND_DATA_WITH_NO_COPY
    *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;
#else
    memcpy(buf, (uint8_t *)stream->body.data + stream->body.sent, n);
    stream->body.sent += n;
#endif

    if (!last)
        return n;

    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
""","read callback chunking")

rep(
"""    return response->http.content_length;
}

static bool server_send_rspmem_persistent(
""",
"""    return n;
}

static bool server_send_rspmem_persistent(
""","read callback return")

rep(
"""    fd = sock->fd;
    ogs_assert(fd != INVALID_SOCKET); /* Check if session is removed */

    nvlen = 3; /* :status && server && date */
""",
"""    fd = sock->fd;
    ogs_assert(fd != INVALID_SOCKET); /* Check if session is removed */

    if (stream->responded) {
        ogs_error("Response already submitted on stream [%d]",
                stream->stream_id);
        return true;
    }

    nvlen = 3; /* :status && server && date */
""","duplicate response guard")

rep(
"""        data_prd.source.ptr = response;
        data_prd.read_callback = response_read_callback;

        ogs_debug("SENDING...: %d", (int)response->http.content_length);
        ogs_debug("%s", response->http.content);
""",
"""        stream->body.data = response->http.content;
        stream->body.len = response->http.content_length;
        response->http.content = NULL;

        data_prd.source.ptr = NULL;
        data_prd.read_callback = response_read_callback;

        ogs_debug("SENDING...: %d", (int)response->http.content_length);
        ogs_debug("%s", (char *)stream->body.data);
""","response ownership")

rep(
"""    } else {
        rv = nghttp2_submit_response(sbi_sess->session,
                stream->stream_id, nva, nvlen, NULL);
    }

    if (rv != OGS_OK) {
""",
"""    } else {
        rv = nghttp2_submit_response(sbi_sess->session,
                stream->stream_id, nva, nvlen, NULL);
    }

    stream->responded = true;

    if (rv != OGS_OK) {
""","response submitted flag")

rep(
"""    ogs_assert(stream->request);
    ogs_sbi_request_free(stream->request);

    ogs_pool_id_free(&stream_pool, stream);
""",
"""    ogs_assert(stream->request);
    ogs_sbi_request_free(stream->request);

    if (stream->body.data)
        ogs_free(stream->body.data);

    ogs_pool_id_free(&stream_pool, stream);
""","stream body free")

# Restrict the next replacements to the on_send_data definition region.
start=s.index("static int on_send_data(nghttp2_session *session, nghttp2_frame *frame,", s.index("#if USE_SEND_DATA_WITH_NO_COPY", 1000))
start=s.index("static int on_send_data(nghttp2_session *session, nghttp2_frame *frame,", start+1)
end=s.index("#else\nstatic ssize_t send_callback", start)
seg=s[start:end]

old="""    ogs_sbi_response_t *response = NULL;
    ogs_sbi_stream_t *stream = NULL;
"""
if seg.count(old)!=1:
    raise SystemExit("on_send_data locals marker")
seg=seg.replace(old,"""    ogs_sbi_stream_t *stream = NULL;
""",1)

old="""    ogs_assert(source);
    response = source->ptr;
    ogs_assert(response);

    ogs_assert(response->http.content);
    ogs_assert(response->http.content_length);

"""
if seg.count(old)!=1:
    raise SystemExit("on_send_data source marker")
seg=seg.replace(old,"""    ogs_assert(stream->body.data);
    ogs_assert(stream->body.len);

""",1)

old="""    ogs_pkbuf_put_data(pkbuf,
            response->http.content, response->http.content_length);
"""
if seg.count(old)!=1:
    raise SystemExit("on_send_data copy marker")
seg=seg.replace(old,"""    ogs_assert(length <= stream->body.len - stream->body.sent);
    ogs_pkbuf_put_data(pkbuf,
            (uint8_t *)stream->body.data + stream->body.sent, length);
    stream->body.sent += length;
""",1)

s=s[:start]+seg+s[end:]
p.write_text(s)

# Provenance markers must all be visible in the resulting source.
for marker in (
    "size_t              sent;",
    "n = ogs_min(length, stream->body.len - stream->body.sent);",
    "response->http.content = NULL;",
    "stream->body.sent += length;",
):
    if marker not in s:
        raise SystemExit(f"missing patched marker: {marker}")

print("patched Open5GS v2.7.6 HTTP/2 response lifetime/chunking path")
