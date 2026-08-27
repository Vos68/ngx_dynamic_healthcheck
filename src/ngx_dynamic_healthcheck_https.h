/*
 * Copyright (C) 2018 Aleksei Konovkin (alkon2000@mail.ru)
 */

#ifndef NGX_DYNAMIC_HEALTHCHECK_HTTPS_H
#define NGX_DYNAMIC_HEALTHCHECK_HTTPS_H


#include "ngx_dynamic_healthcheck_http.h"

#if (NGX_SSL)
extern "C" {
#include <ngx_event_openssl.h>
#include <ngx_palloc.h>
}
#endif


template <class PeersT, class PeerT> class ngx_dynamic_healthcheck_https :
    public ngx_dynamic_healthcheck_http<PeersT, PeerT>
{
#if (NGX_SSL)
    static void
    cleanup_ssl(void *data)
    {
        ngx_dynamic_healthcheck_conf_t *conf =
            (ngx_dynamic_healthcheck_conf_t *) data;

        if (conf->ssl.ctx != NULL)
            ngx_ssl_cleanup_ctx(&conf->ssl);

        ngx_memzero(&conf->ssl, sizeof(ngx_ssl_t));
        conf->ssl_ready = 0;
        conf->ssl_initialized = 0;
    }

    ngx_int_t
    ensure_ssl()
    {
        ngx_pool_cleanup_t *cleanup;

        if (this->event->conf->ssl_initialized)
            return this->event->conf->ssl_ready ? NGX_OK : NGX_ERROR;

        ngx_memzero(&this->event->conf->ssl, sizeof(ngx_ssl_t));
        this->event->conf->ssl.log = ngx_cycle->log;

        if (ngx_ssl_create(&this->event->conf->ssl, default_protocols(), NULL)
            != NGX_OK)
            return NGX_ERROR;

        cleanup = ngx_pool_cleanup_add(ngx_cycle->pool, 0);
        if (cleanup == NULL) {
            ngx_ssl_cleanup_ctx(&this->event->conf->ssl);
            ngx_memzero(&this->event->conf->ssl, sizeof(ngx_ssl_t));
            return NGX_ERROR;
        }

        cleanup->handler = cleanup_ssl;
        cleanup->data = this->event->conf;

        this->event->conf->ssl_ready = 1;
        this->event->conf->ssl_initialized = 1;

        return NGX_OK;
    }

    ngx_int_t
    set_sni_name(ngx_connection_t *c)
    {
        ngx_str_t       host, sni;
        ngx_uint_t      i;
        ngx_keyval_t   *headers;
        u_char         *p;

        ngx_str_null(&host);
        ngx_str_null(&sni);

        headers = this->shared->request_headers.data;
        for (i = 0; i < this->shared->request_headers.len; i++) {
            if (headers[i].key.len == 4
                && ngx_strncasecmp(headers[i].key.data,
                                   (u_char *) "Host", 4) == 0)
            {
                host = headers[i].value;
                break;
            }
        }

        if (host.len == 0)
            return NGX_OK;

        sni = host;
        p = ngx_strlchr(host.data, host.data + host.len, ':');
        if (p != NULL)
            sni.len = p - host.data;

        if (sni.len == 0)
            return NGX_OK;

        p = (u_char *) ngx_alloc(sni.len + 1, c->log);
        if (p == NULL)
            return NGX_ERROR;

        ngx_memcpy(p, sni.data, sni.len);
        p[sni.len] = '\0';

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        if (SSL_set_tlsext_host_name(c->ssl->connection, (char *) p) == 0) {
            ngx_free(p);
            return NGX_ERROR;
        }
#endif

        ngx_free(p);
        return NGX_OK;
    }

    static ngx_uint_t
    default_protocols()
    {
        return NGX_SSL_DEFAULT_PROTOCOLS;
    }

    static void
    handshake_handler(ngx_connection_t *c)
    {
        ngx_dynamic_healthcheck_https<PeersT, PeerT> *peer =
            (ngx_dynamic_healthcheck_https<PeersT, PeerT> *) c->data;

        if (c->ssl == NULL || !c->ssl->handshaked)
            return peer->fail();

        peer->begin_write(c);
    }
#endif

protected:

    virtual ngx_int_t
    on_connected(ngx_connection_t *c)
    {
#if (NGX_SSL)
        ngx_int_t  rc;

        if (c->ssl != NULL && c->ssl->handshaked)
            return NGX_OK;

        if (ensure_ssl() != NGX_OK)
            return NGX_ERROR;

        if (ngx_ssl_create_connection(&this->event->conf->ssl, c,
                                      NGX_SSL_BUFFER | NGX_SSL_CLIENT)
                != NGX_OK)
            return NGX_ERROR;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "hc https ssl connect: c->pool=%p ssl=%p conn=%p",
                       c->pool, c->ssl, c);

        if (set_sni_name(c) != NGX_OK)
            return NGX_ERROR;

        ngx_reusable_connection(c, 0);

        rc = ngx_ssl_handshake(c);
        if (rc == NGX_AGAIN) {
            c->ssl->handler = handshake_handler;
            return NGX_AGAIN;
        }

        return rc;
#else
        return NGX_ERROR;
#endif
    }

public:

    ngx_dynamic_healthcheck_https(PeersT *peers,
        ngx_dynamic_healthcheck_event_t *event, ngx_dynamic_hc_state_node_t s)
        : ngx_dynamic_healthcheck_http<PeersT, PeerT>(peers, event, s)
    {
    }

    virtual ~ngx_dynamic_healthcheck_https() {}
};


#endif /* NGX_DYNAMIC_HEALTHCHECK_HTTPS_H */
