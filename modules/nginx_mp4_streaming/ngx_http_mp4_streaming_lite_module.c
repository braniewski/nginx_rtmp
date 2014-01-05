/*******************************************************************************
 mod_mp4_streaming_lite.c

 mod_mp4_streaming_lite - An nginx plugin for pseudo-streaming Quicktime/MPEG4 files.
 
 Adapted from mod_h264_streaming, the lighttpd plugin
 Original Author: http://h264.code-shop.com
 Original Copyright (C) 2007 CodeShop B.V.

 Nginx module author: Jiang Hong
 Nginx module copyright (C) 2008 Jiang Hong, jh@6.cn

 Note: Only a subset of mp4 files are supported. Contact me if you or your company
 require the full version.

 Tested under:
 - CentOS 5.2
 - FreeBSD 6.2
 - Leopard 10.5.5
 - nginx/0.7.21
 Both 32-bit and 64-bit

 This module compiles but unlikely works on big-endian architectures.

 Revision History:

 2008-10-03
 - Initial version

 2008-11-01
 - start=0 (or 0.0) was allowed in order to send the re-indexed whole file.
 - a directio-related neglect was fixed.
 - mp4_directio directive was removed and the module now follows the server-wide
   directio setting.
 - Content-Length calculation bug was fixed. Thanks go to Nick Melnikov.

 2008-11-13
 - directio-related bug fixed.
 - ngx_open_file_info_t variable not initialized, which causes random access
   problems and pread() errors, has been fixed.

 2008-11-22
 - another Content-Length bug fixed.

 2008-12-05
 - an off-by-one bug fixed.

 2008-12-28
 - more return value checks (reported by Jan Ślusarczyk).

 ----------------------------------------------------------------------------

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
******************************************************************************/

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    /* leave empty */
} ngx_http_mp4_conf_t;

static void *ngx_http_mp4_create_conf(ngx_conf_t *cf);
static char *ngx_http_mp4_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_mp4(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_mp4_lite_commands[] = {

    { ngx_string("mp4"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_mp4,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_mp4_streaming_lite_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_mp4_create_conf,      /* create location configuration */
    ngx_http_mp4_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_mp4_streaming_lite_module = {
    NGX_MODULE_V1,
    &ngx_http_mp4_streaming_lite_module_ctx,      /* module context */
    ngx_http_mp4_lite_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

extern unsigned int
moov_seek(u_char* moov_data,
          unsigned int size,
          float start_time,
          unsigned int* mdat_start,
          unsigned int* mdat_size,
          unsigned int offset);

void
write_char(u_char* outbuffer, int value)
{
    outbuffer[0] = (u_char)(value);
}

void
write_int32(u_char* outbuffer, long value)
{
    outbuffer[0] = (u_char)((value >> 24) & 0xff);
    outbuffer[1] = (u_char)((value >> 16) & 0xff);
    outbuffer[2] = (u_char)((value >> 8) & 0xff);
    outbuffer[3] = (u_char)((value >> 0) & 0xff);
}

struct atom_t
{
    u_char type_[4];
    unsigned int size_;
    unsigned int start_;
    unsigned int end_;
};

#define ATOM_PREAMBLE_SIZE 8

unsigned int
atom_header_size(u_char* atom_bytes)
{
    return (atom_bytes[0] << 24) | (atom_bytes[1] << 16) | (atom_bytes[2] << 8) | (atom_bytes[3]);
}

int
atom_read_header(FILE* infile, struct atom_t* atom)
{
    u_char atom_bytes[ATOM_PREAMBLE_SIZE];

    atom->start_ = ftell(infile);

    if (fread(atom_bytes, 1, ATOM_PREAMBLE_SIZE, infile) != ATOM_PREAMBLE_SIZE) {
        return 0;
    }
    memcpy(&atom->type_[0], &atom_bytes[4], 4);
    atom->size_ = atom_header_size(atom_bytes);
    atom->end_ = atom->start_ + atom->size_;

    return 1;
}

void
atom_write_header(u_char* outbuffer, struct atom_t* atom)
{
    int i;
    write_int32(outbuffer, atom->size_);
    for (i = 0; i != 4; ++i) {
        write_char(outbuffer + 4 + i, atom->type_[i]);
    }
}

int
atom_is(struct atom_t const* atom, const char* type)
{
    return (atom->type_[0] == type[0] && atom->type_[1] == type[1] && atom->type_[2] == type[2] && atom->type_[3] == type[3]);
}

void
atom_skip(FILE* infile, struct atom_t const* atom)
{
    fseek(infile, atom->end_, SEEK_SET);
}

static ngx_int_t
ngx_http_mp4_handler(ngx_http_request_t *r)
{
    u_char                      *p, *last;
    double                      start;
    size_t                      root;
    ngx_int_t                   rc;
    ngx_uint_t                  level;
    ngx_str_t                   path;
    ngx_log_t                   *log;
    ngx_buf_t                   *b;
    ngx_chain_t                 out[10];
    int                         out_index = 0;
    ngx_open_file_info_t        of;
    ngx_http_core_loc_conf_t    *clcf;
    FILE                        *infile;
    struct atom_t               ftyp_atom, moov_atom, mdat_atom;
    u_char                      *moov_data = NULL;
    u_char                      *ftyp_data = NULL;
    u_char                      *mdat_bytes;
    ngx_uint_t                  mdat_start;
    int                         send_entire_file = 0;
    int                         parse_failed = 0;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    /* TODO: Win32 */
#    if (r->zero_in_uri) {
#        return NGX_DECLINED;
#    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http mp4 filename: \"%V\"", &path);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          ngx_open_file_n " \"%s\" failed", path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_DECLINED;
    }

    start = -1;

    if (r->args.len) {

        p = (u_char *) ngx_strnstr(r->args.data, "start=", r->args.len);

        if (p) {
            char param_start[32];
            size_t nlen = 0;
            p += 6;
            while ((p[nlen] >= '0' && p[nlen] <= '9') || p[nlen] == '.') ++nlen;
            if (nlen >= sizeof(param_start))
            {
                start = 0;
            }
            else
            {
                strncpy(param_start, (char*) p, nlen);
                param_start[nlen] = '\0';
                start = strtod(param_start, NULL);
            }
        }
    }

    if (start < 0) {
        send_entire_file = 1;
        goto skip_split;
    }

    memset(&ftyp_atom, 0, sizeof(ftyp_atom));
    memset(&moov_atom, 0, sizeof(moov_atom));
    memset(&mdat_atom, 0, sizeof(mdat_atom));

    infile = fopen((const char*) path.data, "rb");
    if (!infile) {
        return NGX_HTTP_NOT_FOUND;
    }

    while (ftell(infile) < of.size) {

        struct atom_t leaf_atom;

        if (!atom_read_header(infile, &leaf_atom)) {
            parse_failed = 1;
            break;
        }

        if (atom_is(&leaf_atom, "ftyp")) {
            ftyp_atom = leaf_atom;
            ftyp_data = ngx_pcalloc(r->pool, ftyp_atom.size_);
            fseek(infile, ftyp_atom.start_, SEEK_SET);
            if (fread(ftyp_data, 1, ftyp_atom.size_, infile) != ftyp_atom.size_) {
                parse_failed = 1;
                break;
            }
        }
        else if (atom_is(&leaf_atom, "moov")) {
            moov_atom = leaf_atom;
            moov_data = ngx_pcalloc(r->pool, moov_atom.size_);
            fseek(infile, moov_atom.start_, SEEK_SET);
            if (fread(moov_data, 1, moov_atom.size_, infile) != moov_atom.size_) {
                parse_failed = 1;
                break;
            }
        }
        else if (atom_is(&leaf_atom, "mdat")) {
            mdat_atom = leaf_atom;
        }
        atom_skip(infile, &leaf_atom);
    }
    fclose(infile);

    if (parse_failed) {
        return NGX_HTTP_NOT_FOUND;
    }

    mdat_start = (ftyp_data ? ftyp_atom.size_ : 0) + moov_atom.size_;
    if (!moov_seek(moov_data + ATOM_PREAMBLE_SIZE,
                   moov_atom.size_ - ATOM_PREAMBLE_SIZE,
                   start,
                   &mdat_atom.start_, &mdat_atom.size_,
                   mdat_start - mdat_atom.start_)) {
        return NGX_HTTP_NOT_FOUND;
    }

    r->headers_out.content_length_n = 0;

    if (ftyp_data) {
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        b->pos = ftyp_data;
        b->last = b->pos + ftyp_atom.size_;
        b->memory = 1;
        out[out_index].buf = b;
        out[out_index].next = &out[out_index + 1];
        ++out_index;
        r->headers_out.content_length_n += ftyp_atom.size_;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    b->pos = moov_data;
    b->last = b->pos + moov_atom.size_;
    b->memory = 1;
    out[out_index].buf = b;
    out[out_index].next = &out[out_index + 1];
    ++out_index;
    r->headers_out.content_length_n += moov_atom.size_;

    mdat_bytes = ngx_pcalloc(r->pool, ATOM_PREAMBLE_SIZE);
    atom_write_header(mdat_bytes, &mdat_atom);

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    b->pos = mdat_bytes;
    b->last = b->pos + ATOM_PREAMBLE_SIZE;
    b->memory = 1;
    out[out_index].buf = b;
    out[out_index].next = &out[out_index + 1];
    ++out_index;
    r->headers_out.content_length_n += ATOM_PREAMBLE_SIZE;

skip_split:

    log->action = "sending mp4 to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = send_entire_file ? of.size : r->headers_out.content_length_n + mdat_atom.size_ - ATOM_PREAMBLE_SIZE - 1;

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = send_entire_file ? 0 : mdat_atom.start_ + ATOM_PREAMBLE_SIZE;
    b->file_last = send_entire_file ? of.size : b->file_pos + mdat_atom.size_ - ATOM_PREAMBLE_SIZE - 1;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = 1;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out[out_index].buf = b;
    out[out_index].next = NULL;

    return ngx_http_output_filter(r, &out[0]);
}

static void *
ngx_http_mp4_create_conf(ngx_conf_t *cf)
{
    ngx_http_mp4_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mp4_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *
ngx_http_mp4_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
} 

static char *
ngx_http_mp4(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_mp4_handler;

    return NGX_CONF_OK;
}
