/*
 * Copyright (C) Sehyo Chang
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_inet.h>
#include <ngx_stream.h>
#include <sys/socket.h>
#include <linux/netfilter_ipv4.h>

#ifndef IP6T_SO_ORIGINAL_DST
// From linux/netfilter_ipv6/ip6_tables.h
#define IP6T_SO_ORIGINAL_DST 80
#endif


typedef struct {
    ngx_flag_t   enable;
} ngx_stream_orig_dst_srv_conf_t;

typedef struct {
    ngx_str_t    orig_dst_addr;
    ngx_str_t    orig_dst_port;
    ngx_pool_t  *pool;
} ngx_stream_orig_dst_ctx_t;


static ngx_int_t ngx_stream_orig_dst_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_orig_dst_addr_variable(ngx_stream_session_t *s,ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_orig_dst_port_variable(ngx_stream_session_t *s,ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_orig_dst_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_stream_orig_dst_init(ngx_conf_t *cf);
static ngx_int_t ngx_stream_orig_dst_save_ctx(struct sockaddr *addr_in, socklen_t len, ngx_stream_orig_dst_ctx_t *ctx);
static void *ngx_stream_orig_dst_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_orig_dst_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t ngx_stream_orig_dst_commands[] = {

    { ngx_string("use_orig_dst"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_orig_dst_srv_conf_t, enable),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_orig_dst_module_ctx = {
    ngx_stream_orig_dst_add_variables,   /* preconfiguration */
    ngx_stream_orig_dst_init,            /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    ngx_stream_orig_dst_create_srv_conf, /* create server configuration */
    ngx_stream_orig_dst_merge_srv_conf,  /* merge server configuration */
};


ngx_module_t  ngx_stream_orig_dst_module = {
    NGX_MODULE_V1,
    &ngx_stream_orig_dst_module_ctx,     /* module context */
    ngx_stream_orig_dst_commands,        /* module directives */
    NGX_STREAM_MODULE,                   /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_stream_variable_t  ngx_stream_orig_dst_vars[] = {

    { ngx_string("server_orig_addr"), NULL,
      ngx_stream_orig_dst_addr_variable, 0, 0, 0 },

    { ngx_string("server_orig_port"), NULL,
      ngx_stream_orig_dst_port_variable, 0, 0, 0 },

      ngx_stream_null_variable
};

static ngx_int_t
ngx_stream_orig_dst_save_ctx(struct sockaddr *addr_in, socklen_t len, ngx_stream_orig_dst_ctx_t *ctx)
{
    int port;
    u_char ip_str[INET_ADDRSTRLEN];

    ctx->orig_dst_addr.len = ngx_sock_ntop(addr_in, len, ip_str, INET_ADDRSTRLEN, 0);
    if (ctx->orig_dst_addr.len == 0) {
        return NGX_ERROR;
    }
    ctx->orig_dst_addr.data = ngx_pnalloc(ctx->pool, ctx->orig_dst_addr.len);
    if (ctx->orig_dst_addr.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(ctx->orig_dst_addr.data, ip_str, ctx->orig_dst_addr.len);

    port = ngx_inet_get_port(addr_in);
    ctx->orig_dst_port.data = ngx_pnalloc(ctx->pool, sizeof("65535") - 1);
    if (ctx->orig_dst_port.data == NULL) {
        return NGX_ERROR;
    }
    if (port > 0 && port < 65536) {
        ctx->orig_dst_port.len = ngx_sprintf(ctx->orig_dst_port.data, "%ui", port) - ctx->orig_dst_port.data;
    } else {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_orig_dst_handler(ngx_stream_session_t *s)
{
    ngx_stream_orig_dst_srv_conf_t  *odcf;
    struct sockaddr_storage          orig_addr;
    socklen_t                        orig_addr_len;
    ngx_connection_t                *c;
    ngx_stream_orig_dst_ctx_t       *ctx;
    int                              socket_domain;
    int                              status;
    socklen_t                        domain_len;

    c = s->connection;
    orig_addr_len = sizeof(struct sockaddr_storage);
    domain_len = sizeof(socket_domain);

    ngx_log_debug(NGX_LOG_DEBUG_STREAM,  c->log, 0, "orig_dst handler invoked");

    odcf = ngx_stream_get_module_srv_conf(s, ngx_stream_orig_dst_module);

    if (!odcf->enable) {
        return NGX_DECLINED;
    }

    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_orig_dst_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_orig_dst_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_stream_set_ctx(s, ctx, ngx_stream_orig_dst_module);
        ctx->pool = c->pool;
    }

    status = getsockopt(c->fd, SOL_SOCKET, SO_DOMAIN, &socket_domain, &domain_len);
    if (status != 0) {
        return NGX_DECLINED;
    }

    switch (socket_domain) {
    case AF_INET:
        if (getsockopt(c->fd, SOL_IP, SO_ORIGINAL_DST, &orig_addr, &orig_addr_len) == -1) {
            ngx_log_error(NGX_LOG_ALERT, s->connection->log, ngx_socket_errno,
                                          "Failed to get original IPv4 address");
            return NGX_DECLINED;
        }

	break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        if (getsockopt(c->fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &orig_addr, &orig_addr_len) == -1) {
            ngx_log_error(NGX_LOG_ALERT, s->connection->log, ngx_socket_errno,
                                          "Failed to get original IPv6 address");
            return NGX_DECLINED;
        }

	break;
#endif

    default:
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, s->connection->log,  0, "Address is not in INET format");
        return NGX_DECLINED;
    }

    return ngx_stream_orig_dst_save_ctx((struct sockaddr *) &orig_addr, orig_addr_len, ctx);
}


static ngx_int_t
ngx_stream_orig_dst_addr_variable(ngx_stream_session_t *s,
    ngx_variable_value_t *v, uintptr_t data)
{
    ngx_stream_orig_dst_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_orig_dst_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->orig_dst_addr.len;
    v->data = ctx->orig_dst_addr.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_orig_dst_port_variable(ngx_stream_session_t *s,
    ngx_variable_value_t *v, uintptr_t data)
{
    ngx_stream_orig_dst_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_orig_dst_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->orig_dst_port.len;
    v->data = ctx->orig_dst_port.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_orig_dst_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_orig_dst_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_stream_orig_dst_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_orig_dst_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_orig_dst_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_stream_orig_dst_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_orig_dst_srv_conf_t  *prev = parent;
    ngx_stream_orig_dst_srv_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_orig_dst_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_orig_dst_handler;

    return NGX_OK;
}
