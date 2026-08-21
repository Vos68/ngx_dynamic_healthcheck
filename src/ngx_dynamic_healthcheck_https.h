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

        if (!ssl_ready)
            return NGX_ERROR;

        if (ngx_ssl_create_connection(&ssl, c,
                                      NGX_SSL_BUFFER | NGX_SSL_CLIENT)
                != NGX_OK)
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
#if (NGX_SSL)
        , ssl_ready(0)
#endif
    {
#if (NGX_SSL)
        ngx_memzero(&ssl, sizeof(ngx_ssl_t));
        ssl.log = ngx_cycle->log;

        if (ngx_ssl_create(&ssl, 0, NULL) == NGX_OK)
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
