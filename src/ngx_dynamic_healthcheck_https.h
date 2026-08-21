/*
 * Copyright (C) 2018 Aleksei Konovkin (alkon2000@mail.ru)
 */

#ifndef NGX_DYNAMIC_HEALTHCHECK_HTTPS_H
#define NGX_DYNAMIC_HEALTHCHECK_HTTPS_H


#include "ngx_dynamic_healthcheck_http.h"

#if (NGX_SSL)
extern "C" {
#include <ngx_event_openssl.h>
}
#endif


template <class PeersT, class PeerT> class ngx_dynamic_healthcheck_https :
    public ngx_dynamic_healthcheck_http<PeersT, PeerT>
{
#if (NGX_SSL)
    ngx_ssl_t    ssl;
    ngx_flag_t   ssl_ready;

    ngx_str_t
    sni_name(ngx_connection_t *c)
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
            return host;

        sni = host;
        p = ngx_strlchr(host.data, host.data + host.len, ':');
        if (p != NULL)
            sni.len = p - host.data;

        if (sni.len == 0)
            return sni;

        p = (u_char *) ngx_pnalloc(c->pool, sni.len + 1);
        if (p == NULL) {
            ngx_str_null(&sni);
            return sni;
        }

        ngx_memcpy(p, sni.data, sni.len);
        p[sni.len] = '\0';
        sni.data = p;

        return sni;
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
        ngx_str_t  sni;

        if (c->ssl != NULL && c->ssl->handshaked)
            return NGX_OK;

        if (!ssl_ready)
            return NGX_ERROR;

        if (ngx_ssl_create_connection(&ssl, c,
                                      NGX_SSL_BUFFER | NGX_SSL_CLIENT)
                != NGX_OK)
            return NGX_ERROR;

        sni = sni_name(c);
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        if (sni.len != 0
            && SSL_set_tlsext_host_name(c->ssl->connection,
                                        (char *) sni.data) == 0)
        {
            return NGX_ERROR;
        }
#endif

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
#if (NGX_SSL)
        , ssl_ready(0)
#endif
    {
#if (NGX_SSL)
        ngx_memzero(&ssl, sizeof(ngx_ssl_t));
        ssl.log = ngx_cycle->log;

        if (ngx_ssl_create(&ssl, default_protocols(), NULL) == NGX_OK)
            ssl_ready = 1;
#endif
    }

    virtual ~ngx_dynamic_healthcheck_https()
    {
#if (NGX_SSL)
        if (ssl.ctx != NULL)
            ngx_ssl_cleanup_ctx(&ssl);
#endif
    }
};


#endif /* NGX_DYNAMIC_HEALTHCHECK_HTTPS_H */
