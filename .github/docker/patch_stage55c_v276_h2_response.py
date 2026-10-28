#!/usr/bin/env python3
from pathlib import Path

p=Path("/src/open5gs/lib/sbi/nghttp2-server.c")
s=p.read_text()

def replace_once(text, old, new, label):
    n=text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected one marker, found {n}")
    return text.replace(old,new,1)

# 1) Add stream-owned response body state.
s=replace_once(
    s,
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
     * Contextual backport of Open5GS cd1cbc3 + e2e3e55 for v2.7.6.
     * The stream owns deferred response storage and the chunk offset.
     */
    struct {
        void                *data;
        size_t              len;
        size_t              sent;
    } body;
    bool                    responded;
} ogs_sbi_stream_t;
""",
    "stream body state",
)

# 2) Patch only the response data-provider callback.
r0=s.index("static ssize_t response_read_callback(")
r1=s.index("static bool server_send_rspmem_persistent(", r0)
seg=s[r0:r1]
seg=replace_once(
    seg,
"""    ogs_sbi_response_t *response = NULL;
    ogs_sbi_stream_t *stream = NULL;
""",
"""    ogs_sbi_stream_t *stream = NULL;
    size_t n;
    bool last;
""",
    "read callback locals",
)
seg=replace_once(
    seg,
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
""",
    "read callback chunking",
)
seg=replace_once(
    seg,
    "    return response->http.content_length;\n",
    "    return n;\n",
    "read callback return",
)
s=s[:r0]+seg+s[r1:]

# 3) Transfer response ownership to the stream and reject duplicate submits.
d0=s.index(
    "static bool server_send_rspmem_persistent(\n"
    "        ogs_sbi_stream_t *stream, ogs_sbi_response_t *response)\n{"
)
d1=s.index("static bool server_send_response(", d0)
seg=s[d0:d1]
seg=replace_once(
    seg,
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
""",
    "duplicate response guard",
)
seg=replace_once(
    seg,
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
""",
    "response ownership",
)
seg=replace_once(
    seg,
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
""",
    "response submitted flag",
)
s=s[:d0]+seg+s[d1:]

# 4) Free the transferred body when the stream is removed.
m0=s.index("static void stream_remove(ogs_sbi_stream_t *stream)\n{")
m1=s.index("static void stream_remove_all(", m0)
seg=s[m0:m1]
seg=replace_once(
    seg,
"""    ogs_assert(stream->request);
    ogs_sbi_request_free(stream->request);

    ogs_pool_id_free(&stream_pool, stream);
""",
"""    ogs_assert(stream->request);
    ogs_sbi_request_free(stream->request);

    if (stream->body.data)
        ogs_free(stream->body.data);

    ogs_pool_id_free(&stream_pool, stream);
""",
    "stream body free",
)
s=s[:m0]+seg+s[m1:]

# 5) Patch only the actual on_send_data definition, not its prototype.
needle=(
    "static int on_send_data(nghttp2_session *session, nghttp2_frame *frame,\n"
    "                        const uint8_t *framehd, size_t length,\n"
    "                        nghttp2_data_source *source, void *user_data)\n{"
)
o0=s.index(needle)
o1=s.index("#else\nstatic ssize_t send_callback", o0)
seg=s[o0:o1]
seg=replace_once(
    seg,
"""    ogs_sbi_response_t *response = NULL;
    ogs_sbi_stream_t *stream = NULL;
""",
"""    ogs_sbi_stream_t *stream = NULL;
""",
    "on_send_data locals",
)
seg=replace_once(
    seg,
"""    ogs_assert(source);
    response = source->ptr;
    ogs_assert(response);

    ogs_assert(response->http.content);
    ogs_assert(response->http.content_length);

""",
"""    ogs_assert(stream->body.data);
    ogs_assert(stream->body.len);

""",
    "on_send_data source",
)
seg=replace_once(
    seg,
"""    ogs_pkbuf_put_data(pkbuf,
            response->http.content, response->http.content_length);
""",
"""    ogs_assert(length <= stream->body.len - stream->body.sent);
    ogs_pkbuf_put_data(pkbuf,
            (uint8_t *)stream->body.data + stream->body.sent, length);
    stream->body.sent += length;
""",
    "on_send_data chunk copy",
)
s=s[:o0]+seg+s[o1:]

p.write_text(s)

for marker in (
    "size_t              sent;",
    "n = ogs_min(length, stream->body.len - stream->body.sent);",
    "response->http.content = NULL;",
    "stream->body.sent += length;",
    "if (stream->body.data)\n        ogs_free(stream->body.data);",
):
    if marker not in s:
        raise SystemExit(f"missing patched marker: {marker}")

print("patched Open5GS v2.7.6 HTTP/2 response lifetime/chunking path")
