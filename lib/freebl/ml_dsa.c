/*
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "prerror.h"
#include "secerr.h"

#include "prtypes.h"
#include "prinit.h"
#include "blapi.h"
#include "secitem.h"
#include "blapit.h"
#include "secport.h"
#include "nssilock.h"
#include "secrng.h"

#include "lc_dilithium.h"
#include "ml_dsa_api.h"


/*
 * some missing utilities, just use the nss implementations
 */
int
lc_memcmp_secure(const void *s1, size_t s1n, const void *s2, size_t s2n)
{
    /* NSS's secure function takes on one len, get the min length
     * to pass to it the point here is to be constant time... so
     * we do the select checks in constant time: NOTE:this is really
     * only constant time is the min value is constant, but we can't
     * overrun the min buffer */
    PRUint32 s1n_, s2n_, min, res;
    s1n_ = s1n; s2n_= s2n;
    min = PORT_CT_SEL(PORT_CT_LT(s1n_,s2n_), s1n_, s2n_);
    res = NSS_SecureMemcmp(s1, s2, min);
    return (int)PORT_CT_SEL(PORT_CT_EQ(s1n_,s2n_), res, 1);
}

#ifdef notdef
void bin2print(const unsigned char *bin, const size_t binlen, FILE *out,
               const char *explanation) {
        if (explanation)
                fprintf(out, "%s = ", explanation);

        for (int i=0; i < binlen; i++)
            fprintf(out, "%02x",bin[i]);
        fprintf(out,"\n");
}
#endif

struct MLDSAContextStr {
    PLArenaPool *arena;
    MLDSAPrivateKey *privKey;
    MLDSAPublicKey *pubKey;
    CK_HEDGE_TYPE hedgeType;
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet;
    struct lc_dilithium_ctx lc_dilithium;
};

#ifdef notdef
void
hexprint(const char *label, const unsigned char *buf,
         unsigned int len, unsigned int max)
{
    int i;
    fprintf(stderr,"%s(%d): ",label, len);
    len = len > max ? max : len;
    if (len == 0) {
        fprintf(stderr, "null\n");
        return;
    }

    for (i=0; i < len; i++) {
        fprintf(stderr,"%02x",buf[i]);
    }
    fprintf(stderr, "\n");
}
#endif


#ifdef NSS_ENABLE_ML_DSA
static void
mldsa_DestroyContext(MLDSAContext *ctx)
{
    PLArenaPool *arena = ctx->arena;

    /* free up any dangling hashes. Can happen in certain signature
     * failure cases */
    lc_hash_zero(&ctx->lc_dilithium.dilithium_hash_ctx);

    /* this zeros out all the arena allocated data, so we don't have to
     * do any expicit freeing */
    PORT_FreeArena(arena, PR_TRUE);
}

static MLDSAContext *
mldsa_NewContext(const MLDSAPrivateKey *privKey, const MLDSAPublicKey *pubKey)
{
    PLArenaPool *arena = NULL;
    MLDSAContext  *ctx = NULL;

    /* must have one and only one of the keys */
    if (!privKey && !pubKey) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
    }
    if (privKey && pubKey) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
    }
    
    arena = PORT_NewArena(1024);
    if (arena == NULL) {
        return NULL;
    }

    ctx = PORT_ArenaZNew(arena, MLDSAContext);
    if (!ctx) {
        goto loser;
    }
    ctx->arena = arena;
    ctx->lc_dilithium.dilithium_hash_ctx.hash = lc_shake256;
    ctx->lc_dilithium.dilithium_hash_ctx.stream = true;
    /* we ZNew'd the context, so this is not necessary, but
     * document it here or hashing won't work if we don't
     * have a zero'ed context:
    lctx->lc_dilithium.dilithium_hash_ctx.u.ctx_ptr = NULL;  */
    if (privKey) {
        ctx->privKey = PORT_ArenaNew(arena, MLDSAPrivateKey);
        if (ctx->privKey == NULL) {
            goto loser;
        }
        PORT_Memcpy(ctx->privKey, privKey, sizeof(MLDSAPrivateKey));
    }
    if (pubKey) {
        ctx->pubKey = PORT_ArenaNew(arena, MLDSAPublicKey);
        if (ctx->pubKey == NULL) {
            goto loser;
        }
        PORT_Memcpy(ctx->pubKey, pubKey, sizeof(MLDSAPublicKey));
    }
    return ctx;

loser:
    if (ctx) {
        arena = 0;
        mldsa_DestroyContext(ctx);
    }
    if (arena) {
        PORT_FreeArena(arena, PR_FALSE);
    }
    return NULL;
}

static const MLDSAPrivateKey *
mldsa_ContextGetPrivateKey(const MLDSAContext *ctx)
{
    return ctx->privKey;
}

static const MLDSAPublicKey *
mldsa_ContextGetPublicKey(const MLDSAContext *ctx)
{
    return ctx->pubKey;
}
#endif

/*
** Generate and return a new DSA public and private key pair,
**  both of which are encoded into a single DSAPrivateKey struct.
**  "params" is a pointer to the PQG parameters for the domain
**  Uses a random seed.
*/
SECStatus
MLDSA_NewKey(CK_ML_DSA_PARAMETER_SET_TYPE paramSet, SECItem *seed,
              MLDSAPrivateKey *privKey, MLDSAPublicKey *pubKey)
{
#ifndef NSS_ENABLE_ML_DSA
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
#else
    int ret = -1;

    /* make sure we can set the keys first */
    if (!privKey || !pubKey) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    privKey->seedLen = ML_DSA_SEED_LEN;
    privKey->paramSet = paramSet;
    pubKey->paramSet = paramSet;
    if (seed != NULL) {
        if ((seed->data == NULL) || (seed->len != ML_DSA_SEED_LEN)) {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            goto loser;
        }
        PORT_Memcpy(privKey->seed, seed->data, ML_DSA_SEED_LEN);
    } else {
        RNG_SystemRNG(privKey->seed, ML_DSA_SEED_LEN);
    }
    privKey->seedLen = ML_DSA_SEED_LEN;

    switch (paramSet) {
    case CKP_ML_DSA_44:
        ret = lc_dilithium_44_keypair_from_seed_c(
                    (struct lc_dilithium_44_pk *)pubKey->keyVal,
                    (struct lc_dilithium_44_sk *)privKey->keyVal,
                    privKey->seed, privKey->seedLen);
        pubKey->keyValLen = ML_DSA_44_PUBLICKEY_LEN;
        privKey->keyValLen = ML_DSA_44_PRIVATEKEY_LEN;
        break;
    case CKP_ML_DSA_65:
        ret = lc_dilithium_65_keypair_from_seed_c(
                    (struct lc_dilithium_65_pk *)pubKey->keyVal,
                    (struct lc_dilithium_65_sk *)privKey->keyVal,
                    privKey->seed, privKey->seedLen);
        pubKey->keyValLen = ML_DSA_65_PUBLICKEY_LEN;
        privKey->keyValLen = ML_DSA_65_PRIVATEKEY_LEN;
        break;
    case CKP_ML_DSA_87:
        ret = lc_dilithium_87_keypair_from_seed_c(
                    (struct lc_dilithium_87_pk *)pubKey->keyVal,
                    (struct lc_dilithium_87_sk *)privKey->keyVal,
                    privKey->seed, privKey->seedLen);
        pubKey->keyValLen = ML_DSA_87_PUBLICKEY_LEN;
        privKey->keyValLen = ML_DSA_87_PRIVATEKEY_LEN;
        break;
    default:
        ret = -1;
        break;
    }

    if (ret != 0 ) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        goto loser;
    } 
    return SECSuccess;

loser:
    PORT_SafeZero(privKey, sizeof(privKey));
    PORT_SafeZero(pubKey, sizeof(pubKey));
    return SECFailure;
#endif
}

/*
 * we don't have a streaming interace, so use our own local context
 * to keep track of things */
SECStatus
MLDSA_SignInit(MLDSAPrivateKey *key, CK_HEDGE_TYPE hedgeType,
               const SECItem *sgnCtx, MLDSAContext **ctx)
{
#ifndef NSS_ENABLE_ML_DSA
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
#else
    int ret = -1;
    MLDSAContext *lctx = NULL;
    if (!ctx || !key || (sgnCtx && sgnCtx->len > 255)) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    lctx = mldsa_NewContext(key, NULL);
    if (lctx == NULL ) {
        return SECFailure;
    }
    lctx->hedgeType = hedgeType;
    if (sgnCtx && sgnCtx->len != 0) {
        lctx->lc_dilithium.userctx = sgnCtx->data;
        lctx->lc_dilithium.userctxlen = sgnCtx->len;
    }
    lctx->paramSet = key->paramSet;

    switch (key->paramSet) {
    case CKP_ML_DSA_44:
        ret = lc_dilithium_44_sign_init_c(&lctx->lc_dilithium,
                    (struct lc_dilithium_44_sk *)key->keyVal);
        break;
    case CKP_ML_DSA_65:
        ret = lc_dilithium_65_sign_init_c(&lctx->lc_dilithium,
                    (struct lc_dilithium_65_sk *)key->keyVal);
        break;
    case CKP_ML_DSA_87:
        ret = lc_dilithium_87_sign_init_c(&lctx->lc_dilithium,
                    (struct lc_dilithium_87_sk *)key->keyVal);
        break;
   }

    if (ret < 0) {
        mldsa_DestroyContext(lctx);
       return SECFailure;
    }
    *ctx = lctx;
    return SECSuccess;
#endif
}

SECStatus
MLDSA_SignUpdate(MLDSAContext *ctx, const SECItem *data) 
{
#ifndef NSS_ENABLE_ML_DSA
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
#else
    int ret = -1;
    switch (ctx->paramSet) {
    case CKP_ML_DSA_44:
        ret = lc_dilithium_44_sign_update_c(&ctx->lc_dilithium,
                                          data->data, data->len);
        break;
    case CKP_ML_DSA_65:
        ret = lc_dilithium_65_sign_update_c(&ctx->lc_dilithium,
                                          data->data, data->len);
        break;
    case CKP_ML_DSA_87:
        ret = lc_dilithium_87_sign_update_c(&ctx->lc_dilithium,
                                          data->data, data->len);
        break;
   }

    if (ret < 0) {
       return SECFailure;
    }
    return SECSuccess;
#endif
}


SECStatus
MLDSA_SignFinal(MLDSAContext *ctx, SECItem *signature)
{
#ifndef NSS_ENABLE_ML_DSA
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
#else
    /* make sure we have all the parameters */
    if (!ctx || !signature) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    const MLDSAPrivateKey *key = mldsa_ContextGetPrivateKey(ctx);
    int ret = -1;
    size_t len = signature->len;
    struct lc_rng_ctx system_rng = {NULL};
    struct lc_rng_ctx *fake_rng = &system_rng;

    if (!key) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    if (ctx->hedgeType == CKH_DETERMINISTIC_REQUIRED) {
        fake_rng = NULL;
    }
    
    ret = -1;
    switch (key->paramSet) {
        case CKP_ML_DSA_44:
            /* handle the case where we are trying to get the signature length
             * or we supplied a length that was too short */
            len = ML_DSA_44_SIGNATURE_LEN;
            if (!signature->data || 
                (signature->len < len)) {
                signature->len = len;
                PORT_SetError(SEC_ERROR_OUTPUT_LEN);
                break;
            }
            ret = lc_dilithium_44_sign_final_c(
                              (struct lc_dilithium_44_sig *)signature->data,
                              &ctx->lc_dilithium,
                              (struct lc_dilithium_44_sk *)key->keyVal,
                              fake_rng);
            break;
        case CKP_ML_DSA_65:
            /* handle the case where we are trying to get the signature length
             * or we supplied a length that was too short */
            len = ML_DSA_65_SIGNATURE_LEN;
            if (!signature->data || 
                (signature->len < len)) {
                signature->len = len;
                PORT_SetError(SEC_ERROR_OUTPUT_LEN);
                break;
            } 
            ret = lc_dilithium_65_sign_final_c(
                              (struct lc_dilithium_65_sig *)signature->data,
                              &ctx->lc_dilithium,
                              (struct lc_dilithium_65_sk *)key->keyVal,
                              fake_rng);
            break;
        case CKP_ML_DSA_87:
            /* handle the case where we are trying to get the signature length
             * or we supplied a length that was too short */
             len = ML_DSA_87_SIGNATURE_LEN;
            if (!signature->data || 
                (signature->len < len)) {
                signature->len = len;
                PORT_SetError(SEC_ERROR_OUTPUT_LEN);
                break;
            }
            ret = lc_dilithium_87_sign_final_c(
                              (struct lc_dilithium_87_sig *)signature->data,
                              &ctx->lc_dilithium,
                              (struct lc_dilithium_87_sk *)key->keyVal,
                              fake_rng);
            break;
        default:
            ret = -1;
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            break;
    }
    if (ret != 0 ) {
        /* error code already set */
        return SECFailure;
    }
    signature->len = len;
    mldsa_DestroyContext(ctx);
    return SECSuccess;
#endif
}

/*
 * we don't have a streaming interace, so use our own local context
 * to keep track of things */
SECStatus
MLDSA_VerifyInit(MLDSAPublicKey *key, const SECItem *sgnCtx, MLDSAContext **ctx)
{
#ifndef NSS_ENABLE_ML_DSA
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
#else
    MLDSAContext *lctx;
    int ret = -1;
    if (!ctx || !key || (sgnCtx && sgnCtx->len > 255)) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    lctx = mldsa_NewContext(NULL, key);
    if (!lctx) {
        return SECFailure;
    }
    if (sgnCtx && sgnCtx->len != 0) {
        lctx->lc_dilithium.userctx = sgnCtx->data;
        lctx->lc_dilithium.userctxlen = sgnCtx->len;
    }
    lctx->paramSet = key->paramSet;

    switch (key->paramSet) {
    case CKP_ML_DSA_44:
        ret = lc_dilithium_44_verify_init_c(&lctx->lc_dilithium,
                                 (struct lc_dilithium_44_pk *)key->keyVal);
        break;
    case CKP_ML_DSA_65:
        ret = lc_dilithium_65_verify_init_c(&lctx->lc_dilithium,
                                 (struct lc_dilithium_65_pk *)key->keyVal);
        break;
    case CKP_ML_DSA_87:
        ret = lc_dilithium_87_verify_init_c(&lctx->lc_dilithium,
                                 (struct lc_dilithium_87_pk *)key->keyVal);
        break;
    }

    if (ret < 0) {
        mldsa_DestroyContext(lctx);
       return SECFailure;
    }
    *ctx = lctx;
    return SECSuccess;
#endif
}

SECStatus
MLDSA_VerifyUpdate(MLDSAContext *ctx, const SECItem *data) 
{
#ifndef NSS_ENABLE_ML_DSA
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
#else
    int ret = -1;
    switch (ctx->paramSet) {
    case CKP_ML_DSA_44:
         ret = lc_dilithium_44_verify_update_c(&ctx->lc_dilithium,
                                               data->data, data->len);
         break;
    case CKP_ML_DSA_65:
         ret = lc_dilithium_65_verify_update_c(&ctx->lc_dilithium,
                                               data->data, data->len);
         break;
    case CKP_ML_DSA_87:
         ret = lc_dilithium_87_verify_update_c(&ctx->lc_dilithium,
                                               data->data, data->len);
         break;
    }
    
    if (ret < 0) {
       return SECFailure;
    }
    return SECSuccess;
#endif
}

SECStatus
MLDSA_VerifyFinal(MLDSAContext *ctx, const SECItem *signature)
{
#ifndef NSS_ENABLE_ML_DSA
    PORT_SetError(SEC_ERROR_INVALID_ARGS);
    return SECFailure;
#else
    const MLDSAPublicKey *key = mldsa_ContextGetPublicKey(ctx);
    int ret = -1;

    if (key == NULL) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    ret = -1;
    switch (key->paramSet) {
        case CKP_ML_DSA_44:
            ret = lc_dilithium_44_verify_final_c(
             (struct lc_dilithium_44_sig *)signature->data,
             &ctx->lc_dilithium, (struct lc_dilithium_44_pk *)key->keyVal);
            break;
        case CKP_ML_DSA_65:
            ret = lc_dilithium_65_verify_final_c(
             (struct lc_dilithium_65_sig *)signature->data,
             &ctx->lc_dilithium, (struct lc_dilithium_65_pk *)key->keyVal);
            break;
        case CKP_ML_DSA_87:
            ret = lc_dilithium_87_verify_final_c(
             (struct lc_dilithium_87_sig *)signature->data,
             &ctx->lc_dilithium, (struct lc_dilithium_87_pk *)key->keyVal);
            break;
        default:
            ret = -1;
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            break;
    }
    if (ret != 0 ) {
        /* in Verify we close the context on an invalid signature as well
         * as success */
        mldsa_DestroyContext(ctx);
        PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
        return SECFailure;
    }
    mldsa_DestroyContext(ctx);
    return SECSuccess;
#endif
}

