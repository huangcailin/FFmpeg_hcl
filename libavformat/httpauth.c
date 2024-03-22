/*
 * HTTP authentication
 * Copyright (c) 2010 Martin Storsjo
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "httpauth.h"
#include "libavutil/base64.h"
#include "libavutil/avstring.h"
#include "internal.h"
#include "libavutil/random_seed.h"
#include "urldecode.h"
#include <openssl/evp.h>

#define HASHLEN 16
#define HASHHEXLEN 32

static void handle_basic_params(HTTPAuthState *state, const char *key,
                                int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "realm=", key_len)) {
        *dest     =        state->realm;
        *dest_len = sizeof(state->realm);
    }
}

static void handle_digest_params(HTTPAuthState *state, const char *key,
                                 int key_len, char **dest, int *dest_len)
{
    DigestParams *digest = &state->digest_params;

    if (!strncmp(key, "realm=", key_len)) {
        *dest     =        state->realm;
        *dest_len = sizeof(state->realm);
    } else if (!strncmp(key, "nonce=", key_len)) {
        *dest     =        digest->nonce;
        *dest_len = sizeof(digest->nonce);
    } else if (!strncmp(key, "opaque=", key_len)) {
        *dest     =        digest->opaque;
        *dest_len = sizeof(digest->opaque);
    } else if (!strncmp(key, "algorithm=", key_len)) {
        *dest     =        digest->algorithm;
        *dest_len = sizeof(digest->algorithm);
    } else if (!strncmp(key, "qop=", key_len)) {
        *dest     =        digest->qop;
        *dest_len = sizeof(digest->qop);
    } else if (!strncmp(key, "stale=", key_len)) {
        *dest     =        digest->stale;
        *dest_len = sizeof(digest->stale);
    }
}

static void handle_digest_update(HTTPAuthState *state, const char *key,
                                 int key_len, char **dest, int *dest_len)
{
    DigestParams *digest = &state->digest_params;

    if (!strncmp(key, "nextnonce=", key_len)) {
        *dest     =        digest->nonce;
        *dest_len = sizeof(digest->nonce);
    }
}

static void choose_qop(char *qop, int size)
{
    char *ptr = strstr(qop, "auth");
    char *end = ptr + strlen("auth");

    if (ptr && (!*end || av_isspace(*end) || *end == ',') &&
        (ptr == qop || av_isspace(ptr[-1]) || ptr[-1] == ',')) {
        av_strlcpy(qop, "auth", size);
    } else {
        qop[0] = 0;
    }
}

void ff_http_auth_handle_header(HTTPAuthState *state, const char *key,
                                const char *value)
{
    if (!av_strcasecmp(key, "WWW-Authenticate") || !av_strcasecmp(key, "Proxy-Authenticate")) {
        const char *p;
        if (av_stristart(value, "Basic ", &p) &&
            state->auth_type <= HTTP_AUTH_BASIC) {
            state->auth_type = HTTP_AUTH_BASIC;
            state->realm[0] = 0;
            state->stale = 0;
            ff_parse_key_value(p, (ff_parse_key_val_cb) handle_basic_params,
                               state);
        } else if (av_stristart(value, "Digest ", &p) &&
                   state->auth_type <= HTTP_AUTH_DIGEST) {
            state->auth_type = HTTP_AUTH_DIGEST;
            memset(&state->digest_params, 0, sizeof(DigestParams));
            state->realm[0] = 0;
            state->stale = 0;
            ff_parse_key_value(p, (ff_parse_key_val_cb) handle_digest_params,
                               state);
            choose_qop(state->digest_params.qop,
                       sizeof(state->digest_params.qop));
            if (!av_strcasecmp(state->digest_params.stale, "true"))
                state->stale = 1;
        }
    } else if (!av_strcasecmp(key, "Authentication-Info")) {
        ff_parse_key_value(value, (ff_parse_key_val_cb) handle_digest_update,
                           state);
    }
}


/* Generate a digest reply, according to RFC 2617. */
static char *make_digest_auth(HTTPAuthState *state, const char *username,
                              const char *password, const char *uri,
                              const char *method)
{
    DigestParams *digest = &state->digest_params;
    int len;
    uint32_t cnonce_buf[2];
    char cnonce[17];
    char nc[9];
    int i;
    char A1hash[EVP_MAX_MD_SIZE+1], md_value[EVP_MAX_MD_SIZE],HA2[EVP_MAX_MD_SIZE],A2hash[EVP_MAX_MD_SIZE+1], response[EVP_MAX_MD_SIZE+1];
    char *authstr;
    const EVP_MD *md=NULL;
    unsigned int iBinLen = 0;
    unsigned int iHexLen = 0;
    unsigned int    digestlength = 0;

    digest->nc++;
    snprintf(nc, sizeof(nc), "%08x", digest->nc);

    /* Generate a client nonce. */
    for (i = 0; i < 2; i++)
        cnonce_buf[i] = av_get_random_seed();
    ff_data_to_hex(cnonce, (const uint8_t*) cnonce_buf, sizeof(cnonce_buf), 1);

    EVP_MD_CTX *md5ctx = NULL;
    md5ctx = EVP_MD_CTX_new();
    if (!md5ctx)
        return NULL;

    if(strcmp(digest->algorithm, "md5-sess") == 0 || strcmp(digest->algorithm, "MD5") == 0)
    {
        iBinLen = HASHLEN;
        iHexLen = HASHHEXLEN;
        md = EVP_md5();
    }
    else if(strcmp(digest->algorithm, "SHA-256") == 0 || strcmp(digest->algorithm, "SHA256") == 0)
    {
        iBinLen = HASHHEXLEN;
        iHexLen = EVP_MAX_MD_SIZE;
        md = EVP_sha256();
    }
    if (md == NULL)
        return NULL;

    EVP_MD_CTX_init(md5ctx);

    EVP_DigestInit_ex(md5ctx, md, NULL);

    EVP_DigestUpdate(md5ctx, (unsigned char*)username, strlen(username));
    EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
    EVP_DigestUpdate(md5ctx, (unsigned char*)state->realm, strlen(state->realm));
    EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
    EVP_DigestUpdate(md5ctx, (unsigned char*)password, strlen(password));
    EVP_DigestFinal(md5ctx, (unsigned char*)md_value, &digestlength);
    ff_data_to_hex(A1hash, md_value, sizeof(md_value), 1);
    if(!strcmp(digest->algorithm, "MD5-sess")) {
        EVP_DigestInit_ex(md5ctx, md, NULL);
        EVP_DigestUpdate(md5ctx, (unsigned char*)A1hash, iBinLen);
        EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
        EVP_DigestUpdate(md5ctx, (unsigned char*)digest->nonce, strlen(digest->nonce));
        EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
        EVP_DigestUpdate(md5ctx, (unsigned char*)cnonce, strlen(cnonce));
        EVP_DigestFinal(md5ctx, (unsigned char*)md_value, &digestlength);
        ff_data_to_hex(A1hash, md_value, sizeof(md_value), 1);
    } else {
        /* Unsupported algorithm */
        av_free(md5ctx);
        return NULL;
    }

    EVP_MD_CTX_init(md5ctx);
    EVP_DigestInit_ex(md5ctx, md, NULL);
    EVP_DigestInit_ex(md5ctx, md, NULL);
    EVP_DigestUpdate(md5ctx, (unsigned char*)method, strlen(method));
    EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
    EVP_DigestUpdate(md5ctx, (unsigned char*)uri, strlen(uri));
    if (strcmp(digest->qop, "auth-int") == 0) {
        EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
    };
    
    EVP_DigestFinal(md5ctx, HA2, &digestlength);
    ff_data_to_hex(A2hash, HA2, sizeof(HA2), 1);

    EVP_DigestInit_ex(md5ctx, md, NULL);
    EVP_DigestUpdate(md5ctx, (unsigned char*)A1hash, sizeof(A1hash));
    EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
    EVP_DigestUpdate(md5ctx, (unsigned char*)digest->nonce, strlen(digest->nonce));
    EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
    if (!strcmp(digest->qop, "auth") || !strcmp(digest->qop, "auth-int")) {
        EVP_DigestUpdate(md5ctx, (unsigned char*)nc, strlen(nc));
        EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
        EVP_DigestUpdate(md5ctx, (unsigned char*)cnonce, strlen(cnonce));
        EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
        EVP_DigestUpdate(md5ctx, (unsigned char*)digest->qop, strlen(digest->qop));
        EVP_DigestUpdate(md5ctx, (unsigned char*)":", 1);
    }
    EVP_DigestUpdate(md5ctx, (unsigned char*)A2hash, iHexLen);
    unsigned int    digestRespHash = 0;
    EVP_DigestFinal(md5ctx, (unsigned char*)md_value, &digestRespHash);
    ff_data_to_hex(response, md_value, sizeof(md_value), 1);

    av_free(md5ctx);

    if (!strcmp(digest->qop, "") || !strcmp(digest->qop, "auth")) {
    } else if (!strcmp(digest->qop, "auth-int")) {
        /* qop=auth-int not supported */
        return NULL;
    } else {
        /* Unsupported qop value. */
        return NULL;
    }

    len = strlen(username) + strlen(state->realm) + strlen(digest->nonce) +
              strlen(uri) + strlen(response) + strlen(digest->algorithm) +
              strlen(digest->opaque) + strlen(digest->qop) + strlen(cnonce) +
              strlen(nc) + 150;

    authstr = av_malloc(len);
    if (!authstr)
        return NULL;
    snprintf(authstr, len, "Authorization: Digest ");

    /* TODO: Escape the quoted strings properly. */
    av_strlcatf(authstr, len, "username=\"%s\"",   username);
    av_strlcatf(authstr, len, ", realm=\"%s\"",     state->realm);
    av_strlcatf(authstr, len, ", nonce=\"%s\"",     digest->nonce);
    av_strlcatf(authstr, len, ", uri=\"%s\"",       uri);
    av_strlcatf(authstr, len, ", response=\"%s\"",  response);

    // we are violating the RFC and use "" because all others seem to do that too.
    if (digest->algorithm[0])
        av_strlcatf(authstr, len, ", algorithm=\"%s\"",  digest->algorithm);

    if (digest->opaque[0])
        av_strlcatf(authstr, len, ", opaque=\"%s\"", digest->opaque);
    if (digest->qop[0]) {
        av_strlcatf(authstr, len, ", qop=\"%s\"",    digest->qop);
        av_strlcatf(authstr, len, ", cnonce=\"%s\"", cnonce);
        av_strlcatf(authstr, len, ", nc=%s",         nc);
    }

    av_strlcatf(authstr, len, "\r\n");

    return authstr;
}

char *ff_http_auth_create_response(HTTPAuthState *state, const char *auth,
                                   const char *path, const char *method)
{
    char *authstr = NULL;

    /* Clear the stale flag, we assume the auth is ok now. It is reset
     * by the server headers if there's a new issue. */
    state->stale = 0;
    if (!auth || !strchr(auth, ':'))
        return NULL;

    if (state->auth_type == HTTP_AUTH_BASIC) {
        int auth_b64_len, len;
        char *ptr, *decoded_auth = ff_urldecode(auth, 0);

        if (!decoded_auth)
            return NULL;

        auth_b64_len = AV_BASE64_SIZE(strlen(decoded_auth));
        len = auth_b64_len + 30;

        authstr = av_malloc(len);
        if (!authstr) {
            av_free(decoded_auth);
            return NULL;
        }

        snprintf(authstr, len, "Authorization: Basic ");
        ptr = authstr + strlen(authstr);
        av_base64_encode(ptr, auth_b64_len, decoded_auth, strlen(decoded_auth));
        av_strlcat(ptr, "\r\n", len - (ptr - authstr));
        av_free(decoded_auth);
    } else if (state->auth_type == HTTP_AUTH_DIGEST) {
        char *username = ff_urldecode(auth, 0), *password;

        if (!username)
            return NULL;

        if ((password = strchr(username, ':'))) {
            *password++ = 0;
            authstr = make_digest_auth(state, username, password, path, method);
        }
        av_free(username);
    }
    return authstr;
}
