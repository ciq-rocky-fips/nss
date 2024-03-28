/* P-384 from HACL* */

#ifdef FREEBL_NO_DEPEND
#include "../stubs.h"
#endif

#include "ecl-priv.h"
#include "secitem.h"
#include "secerr.h"
#include "secmpi.h"
#include "../verified/Hacl_P384.h"

/*
 * Point Validation for P-384.
 */

SECStatus
ec_secp384r1_pt_validate(const SECItem *pt)
{
    SECStatus res = SECSuccess;
    if (!pt || !pt->data) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        res = SECFailure;
        return res;
    }

    if (pt->len != 97) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        res = SECFailure;
        return res;
    }

    if (pt->data[0] != EC_POINT_FORM_UNCOMPRESSED) {
        PORT_SetError(SEC_ERROR_UNSUPPORTED_EC_POINT_FORM);
        res = SECFailure;
        return res;
    }

    bool b = Hacl_P384_validate_public_key(pt->data + 1);

    if (!b) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        res = SECFailure;
    }
    return res;
}

/*
 * Scalar multiplication for P-384.
 * If P == NULL, the base point is used.
 * Returns X = k*P
 */

SECStatus
ec_secp384r1_pt_mul(SECItem *X, SECItem *k, SECItem *P)
{
    SECStatus res = SECSuccess;
    if (!P) {
        uint8_t derived[96] = { 0 };

        if (!X || !k || !X->data || !k->data ||
            X->len < 97 || k->len != 48) {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            res = SECFailure;
            return res;
        }

        bool b = Hacl_P384_dh_initiator(derived, k->data);

        if (!b) {
            PORT_SetError(SEC_ERROR_BAD_KEY);
            res = SECFailure;
            return res;
        }

        X->len = 97;
        X->data[0] = EC_POINT_FORM_UNCOMPRESSED;
        memcpy(X->data + 1, derived, 96);

    } else {
        uint8_t full_key[48] = { 0 };
        uint8_t *key;
        uint8_t derived[96] = { 0 };

        if (!X || !k || !P || !X->data || !k->data || !P->data ||
            X->len < 48 || P->len != 97 ||
            P->data[0] != EC_POINT_FORM_UNCOMPRESSED) {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            res = SECFailure;
            return res;
        }

        /* We consider keys of up to size 48, or of size 49 with a single leading 0 */
        if (k->len < 48) {
            memcpy(full_key + 48 - k->len, k->data, k->len);
            key = full_key;
        } else if (k->len == 48) {
            key = k->data;
        } else if (k->len == 49 && k->data[0] == 0) {
            key = k->data + 1;
        } else {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            res = SECFailure;
            return res;
        }

        bool b = Hacl_P384_dh_responder(derived, P->data + 1, key);

        if (!b) {
            PORT_SetError(SEC_ERROR_BAD_KEY);
            res = SECFailure;
            return res;
        }

        X->len = 48;
        memcpy(X->data, derived, 48);
    }

    return res;
}

/*
 * ECDSA Signature for P-384
 */

SECStatus
ec_secp384r1_sign_digest(ECPrivateKey *key, SECItem *signature,
                         const SECItem *digest, const unsigned char *kb,
                         const unsigned int kblen)
{
    SECStatus res = SECSuccess;

    if (!key || !signature || !digest || !kb ||
        !key->privateValue.data ||
        !signature->data || !digest->data ||
        key->ecParams.name != ECCurve_NIST_P384) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        res = SECFailure;
        return res;
    }

    if (key->privateValue.len != 48 ||
        kblen == 0 ||
        digest->len == 0 ||
        signature->len < 96) {
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        res = SECFailure;
        return res;
    }

    uint8_t hash[48] = { 0 };
    if (digest->len < 48) {
        memcpy(hash + 48 - digest->len, digest->data, digest->len);
    } else {
        memcpy(hash, digest->data, 48);
    }

    uint8_t nonce[48] = { 0 };
    if (kblen < 48) {
        memcpy(nonce + 48 - kblen, kb, kblen);
    } else {
        memcpy(nonce, kb, 48);
    }

    bool b = Hacl_P384_ecdsa_sign_p384_without_hash(
        signature->data, 48, hash,
        key->privateValue.data, nonce);
    if (!b) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        res = SECFailure;
        return res;
    }

    signature->len = 96;
    return res;
}

/*
 * ECDSA Signature Verification for P-384
 */

SECStatus
ec_secp384r1_verify_digest(ECPublicKey *key, const SECItem *signature,
                           const SECItem *digest)
{
    SECStatus res = SECSuccess;

    if (!key || !signature || !digest ||
        !key->publicValue.data ||
        !signature->data || !digest->data ||
        key->ecParams.name != ECCurve_NIST_P384) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        res = SECFailure;
        return res;
    }

    if (key->publicValue.len != 97 ||
        digest->len == 0 ||
        signature->len != 96) {
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        res = SECFailure;
        return res;
    }

    if (key->publicValue.data[0] != EC_POINT_FORM_UNCOMPRESSED) {
        PORT_SetError(SEC_ERROR_UNSUPPORTED_EC_POINT_FORM);
        res = SECFailure;
        return res;
    }

    uint8_t hash[48] = { 0 };
    if (digest->len < 48) {
        memcpy(hash + 48 - digest->len, digest->data, digest->len);
    } else {
        memcpy(hash, digest->data, 48);
    }

    bool b = Hacl_P384_ecdsa_verif_without_hash(
        48, hash,
        key->publicValue.data + 1,
        signature->data, signature->data + 48);
    if (!b) {
        PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
        res = SECFailure;
        return res;
    }

    return res;
}
