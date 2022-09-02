/*
 * Copyright (c) 2010-2012 Frank Morgner and Dominik Oepen
 *
 * This file is part of OpenPACE.
 *
 * OpenPACE is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * OpenPACE is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * OpenPACE.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with OpenSSL (or a modified version of that library), containing
 * parts covered by the terms of OpenSSL's license, the licensors of
 * this Program grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination shall include
 * the source code for the parts of OpenSSL used as well as that of the
 * covered work.
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with OpenSC (or a modified version of that library), containing
 * parts covered by the terms of OpenSC's license, the licensors of
 * this Program grant you additional permission to convey the resulting work. 
 * Corresponding Source for a non-source form of such a combination shall include
 * the source code for the parts of OpenSC used as well as that of the
 * covered work.
 */

/**
 * @file eac_lib.c
 * @brief Data management functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#include "ca_lib.h"
#include "eac_dh.h"
#include "eac_ecdh.h"
#include "eac_err.h"
#include "eac_lib.h"
#include "eac_util.h"
#include "misc.h"
#include "fido_sgx_ca.h"
#include <eac/eac.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <string.h>


void EAC_init(void)
{
    OpenSSL_add_all_algorithms();
    EAC_add_all_objects();
    //EAC_set_x509_default_dir(X509DIR);
}

void EAC_cleanup(void)
{
    EAC_remove_all_objects();
    EVP_cleanup();
}

EPASS_CTX *
EPASS_CTX_new(void)
{
    EPASS_CTX *ctx = OPENSSL_zalloc(sizeof(EPASS_CTX));
    if (!ctx)
        return NULL;

//    ctx->bn_ctx = BN_CTX_new();
    ctx->ca_ctxs = (STACK_OF(CA_CTX *)) sk_new_null();
//    ctx->cipher_ctx = EVP_CIPHER_CTX_new();
//    ctx->md_ctx = EVP_MD_CTX_create();
    ctx->ssc = BN_new();

    //!ctx->bn_ctx || !ctx->md_ctx || !ctx->cipher_ctx
    if (!ctx->ca_ctxs || !ctx->ssc)
        goto err;

//    EVP_CIPHER_CTX_init(ctx->cipher_ctx);
//    ctx->tr_version = EAC_TR_VERSION_2_02;

    ctx->lookup_csca_cert = EAC_get_default_csca_lookup();

    return ctx;

err:
    EPASS_CTX_clear_free(ctx);
    return NULL;
}



static void
wrap_ca_ctx_clear_free(void *ctx)
{
    CA_CTX_clear_free(ctx);
}

void
EPASS_CTX_clear_free(EPASS_CTX *ctx)
{
    if (ctx) {
#if 0
        if (ctx->bn_ctx)
            BN_CTX_free(ctx->bn_ctx);
        if (ctx->md_ctx)
            EVP_MD_CTX_destroy(ctx->md_ctx);
        if (ctx->cipher_ctx)
            EVP_CIPHER_CTX_free(ctx->cipher_ctx);
#endif
        sk_pop_free((_STACK *) ctx->ca_ctxs, wrap_ca_ctx_clear_free);
        KA_CTX_clear_free(ctx->key_ctx);
        if (ctx->ssc)
            BN_clear_free(ctx->ssc);

        // At the moment we inefficiently copy the DG data buffers into new
        // (malloced) heap buffers
        for (unsigned int i=0; i<ctx->dg_num; i++) {
            free(ctx->dgs[i]);
            ctx->dgs[i] = NULL;
        }

        OPENSSL_free(ctx);
    }
}

KA_CTX *
KA_CTX_new(void)
{
    KA_CTX * out = OPENSSL_zalloc(sizeof(KA_CTX));
    if (!out)
        goto err;

    out->key = EVP_PKEY_new();
    if (!out->key)
        goto err;

    return out;

err:
    if (out) {
        if (out->key)
            EVP_PKEY_free(out->key);
        OPENSSL_free(out);
    }
    return NULL;
}

KA_CTX *
KA_CTX_dup(const KA_CTX *ka_ctx)
{
    KA_CTX *out = NULL;

    check(ka_ctx, "Invalid arguments");

    out = OPENSSL_zalloc(sizeof(KA_CTX));
    if (!out)
        goto err;

    out->key = EVP_PKEY_dup(ka_ctx->key);
    if (!out->key && ka_ctx->key)
        goto err;

    out->md = ka_ctx->md;
    out->md_engine = ka_ctx->md_engine;
    out->cipher = ka_ctx->cipher;
    out->cipher_engine = ka_ctx->cipher_engine;
    out->generate_key = ka_ctx->generate_key;
    out->compute_key = ka_ctx->compute_key;
    out->mac_keylen = ka_ctx->mac_keylen;
    out->enc_keylen = ka_ctx->enc_keylen;
    if (ka_ctx->k_enc) {
        out->k_enc = BUF_MEM_create_init(ka_ctx->k_enc->data, ka_ctx->k_enc->length);
        if (!out->k_enc)
            goto err;
    }
    if (ka_ctx->k_mac) {
        out->k_mac = BUF_MEM_create_init(ka_ctx->k_mac->data, ka_ctx->k_mac->length);
        if (!out->k_mac)
            goto err;
    }
    if (ka_ctx->shared_secret) {
        out->shared_secret = BUF_MEM_create_init(ka_ctx->shared_secret->data, ka_ctx->shared_secret->length);
        if (!out->shared_secret)
            goto err;
    }

    return out;

err:
    KA_CTX_clear_free(out);

    return NULL;
}

void
KA_CTX_clear_free(KA_CTX *ctx)
{
    if (ctx) {
        if (ctx->cmac_ctx)
            CMAC_CTX_free(ctx->cmac_ctx);
        if (ctx->key)
            EVP_PKEY_free(ctx->key);
        if (ctx->peer_pubkey)
            EVP_PKEY_free(ctx->peer_pubkey);
        if (ctx->shared_secret) {
            OPENSSL_cleanse(ctx->shared_secret->data, ctx->shared_secret->max);
            BUF_MEM_free(ctx->shared_secret);
        }
        if (ctx->k_mac) {
            OPENSSL_cleanse(ctx->k_mac->data, ctx->k_mac->max);
            BUF_MEM_free(ctx->k_mac);
        }
        if (ctx->k_enc) {
            OPENSSL_cleanse(ctx->k_enc->data, ctx->k_enc->max);
            BUF_MEM_free(ctx->k_enc);
        }
        OPENSSL_free(ctx->iv);
        OPENSSL_free(ctx);
    }
}

int
KA_CTX_set_protocol(KA_CTX *ctx, int protocol)
{
    if (!ctx) {
        log_err("Invalid arguments");
        return 0;
    }

    if (       protocol == NID_id_CA_DH_3DES_CBC_CBC
            || protocol == NID_id_PACE_DH_GM_3DES_CBC_CBC
            || protocol == NID_id_PACE_DH_IM_3DES_CBC_CBC) {
        ctx->generate_key = dh_generate_key;
        ctx->compute_key = dh_compute_key;
        ctx->mac_keylen = 16;
        ctx->md = EVP_sha1();
        ctx->cipher = EVP_des_ede_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_DH_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_DH_GM_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_DH_IM_AES_CBC_CMAC_128) {
        ctx->generate_key = dh_generate_key;
        ctx->compute_key = dh_compute_key;
        ctx->mac_keylen = 16;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha1();
        ctx->cipher = EVP_aes_128_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_DH_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_DH_GM_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_DH_IM_AES_CBC_CMAC_192) {
        ctx->generate_key = dh_generate_key;
        ctx->compute_key = dh_compute_key;
        ctx->mac_keylen = 24;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha256();
        ctx->cipher = EVP_aes_192_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_DH_AES_CBC_CMAC_256
            || protocol == NID_id_PACE_DH_GM_AES_CBC_CMAC_256
            || protocol == NID_id_PACE_DH_IM_AES_CBC_CMAC_256) {
        ctx->generate_key = dh_generate_key;
        ctx->compute_key = dh_compute_key;
        ctx->mac_keylen = 32;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha256();
        ctx->cipher = EVP_aes_256_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_ECDH_3DES_CBC_CBC
            || protocol == NID_id_PACE_ECDH_GM_3DES_CBC_CBC
            || protocol == NID_id_PACE_ECDH_IM_3DES_CBC_CBC) {
        ctx->generate_key = ecdh_generate_key;
        ctx->compute_key = ecdh_compute_key;
        ctx->mac_keylen = 16;
        ctx->md = EVP_sha1();
        ctx->cipher = EVP_des_ede_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_ECDH_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_128
            || protocol == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_128) {
        ctx->generate_key = ecdh_generate_key;
        ctx->compute_key = ecdh_compute_key;
        ctx->mac_keylen = 16;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha1();
        ctx->cipher = EVP_aes_128_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_ECDH_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_192
            || protocol == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_192) {
        ctx->generate_key = ecdh_generate_key;
        ctx->compute_key = ecdh_compute_key;
        ctx->mac_keylen = 24;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha256();
        ctx->cipher = EVP_aes_192_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else if (protocol == NID_id_CA_ECDH_AES_CBC_CMAC_256
            || protocol == NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256
            || protocol == NID_id_PACE_ECDH_IM_AES_CBC_CMAC_256) {
        ctx->generate_key = ecdh_generate_key;
        ctx->compute_key = ecdh_compute_key;
        ctx->mac_keylen = 32;
        ctx->cmac_ctx = NULL; /* We don't set cmac_ctx, because of potential segfaults */
        ctx->md = EVP_sha256();
        ctx->cipher = EVP_aes_256_cbc();
        ctx->enc_keylen = EVP_CIPHER_key_length(ctx->cipher);

    } else {
        log_err("Unknown protocol");
        return 0;
    }

    return 1;
}
