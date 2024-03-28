/* P-384 from HACL* */

#ifdef FREEBL_NO_DEPEND
#include "../stubs.h"
#endif

#include "ecl-priv.h"
#include "secitem.h"
#include "secerr.h"
#include "secmpi.h"
#include "../verified/Hacl_P521.h"

/*
 * Point Validation for P-521.
 */

SECStatus
ec_secp521r1_pt_validate(const SECItem *pt)
{
    SECStatus res = SECSuccess;
    if (!pt || !pt->data) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        res = SECFailure;
        return res;
    }

    if (pt->len != 133) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        res = SECFailure;
        return res;
    }

    if (pt->data[0] != EC_POINT_FORM_UNCOMPRESSED) {
        PORT_SetError(SEC_ERROR_UNSUPPORTED_EC_POINT_FORM);
        res = SECFailure;
        return res;
    }

    bool b = Hacl_P521_validate_public_key(pt->data + 1);

    if (!b) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        res = SECFailure;
    }
    return res;
}

/*
 * Scalar multiplication for P-521.
 * If P == NULL, the base point is used.
 * Returns X = k*P
 */

SECStatus
ec_secp521r1_pt_mul(SECItem *X, SECItem *k, SECItem *P)
{
    SECStatus res = SECSuccess;
    if (!P) {
        uint8_t derived[132] = { 0 };

        if (!X || !k || !X->data || !k->data ||
            X->len < 133 || k->len != 66) {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            res = SECFailure;
            return res;
        }

        bool b = Hacl_P521_dh_initiator(derived, k->data);

        if (!b) {
            PORT_SetError(SEC_ERROR_BAD_KEY);
            res = SECFailure;
            return res;
        }

        X->len = 133;
        X->data[0] = EC_POINT_FORM_UNCOMPRESSED;
        memcpy(X->data + 1, derived, 132);

    } else {
        uint8_t full_key[66] = { 0 };
        uint8_t *key;
        uint8_t derived[132] = { 0 };

        if (!X || !k || !P || !X->data || !k->data || !P->data ||
            X->len < 66 || P->len != 133 ||
            P->data[0] != EC_POINT_FORM_UNCOMPRESSED) {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            res = SECFailure;
            return res;
        }

        /* We consider keys of up to size 66, or of size 67 with a single leading 0 */
        if (k->len < 66) {
            memcpy(full_key + 66 - k->len, k->data, k->len);
            key = full_key;
        } else if (k->len == 66) {
            key = k->data;
        } else if (k->len == 67 && k->data[0] == 0) {
            key = k->data + 1;
        } else {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            res = SECFailure;
            return res;
        }

        bool b = Hacl_P521_dh_responder(derived, P->data + 1, key);

        if (!b) {
            PORT_SetError(SEC_ERROR_BAD_KEY);
            res = SECFailure;
            return res;
        }

        X->len = 66;
        memcpy(X->data, derived, 66);
    }

    return res;
}

/*
 * ECDSA Signature for P-521
 */

SECStatus
ec_secp521r1_sign_digest(ECPrivateKey *key, SECItem *signature,
                         const SECItem *digest, const unsigned char *kb,
                         const unsigned int kblen)
{
    SECStatus res = SECSuccess;

    if (!key || !signature || !digest || !kb ||
        !key->privateValue.data ||
        !signature->data || !digest->data ||
        key->ecParams.name != ECCurve_NIST_P521) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        res = SECFailure;
        return res;
    }

    if (key->privateValue.len != 66 ||
        kblen == 0 ||
        digest->len == 0 ||
        signature->len < 132) {
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        res = SECFailure;
        return res;
    }

    uint8_t hash[66] = { 0 };
    if (digest->len < 66) {
        memcpy(hash + 66 - digest->len, digest->data, digest->len);
    } else {
      // SEC 1 takes the most significant ceil(log(n)) bits of hash output when the hash output is longer than log(n).
        hash[0] = digest->data[0] >> 7;
	for (size_t i=1; i<66; i++) {
	hash[i] = (digest->data[i-1] << 1) | (digest->data[i] >> 7);
	}
    }

    uint8_t nonce[66] = { 0 };
    if (kblen < 66) {
        memcpy(nonce + 66 - kblen, kb, kblen);
    } else {
        memcpy(nonce, kb, 66);
    }

    bool b = Hacl_P521_ecdsa_sign_p521_without_hash(
        signature->data, 66, hash,
        key->privateValue.data, nonce);
    if (!b) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        res = SECFailure;
        return res;
    }

    signature->len = 132;
    return res;
}

/*
 * ECDSA Signature Verification for P-521
 */

SECStatus
ec_secp521r1_verify_digest(ECPublicKey *key, const SECItem *signature,
                           const SECItem *digest)
{
    SECStatus res = SECSuccess;

    if (!key || !signature || !digest ||
        !key->publicValue.data ||
        !signature->data || !digest->data ||
        key->ecParams.name != ECCurve_NIST_P521) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        res = SECFailure;
        return res;
    }

    if (key->publicValue.len != 133 ||
        digest->len == 0 ||
        signature->len != 132) {
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        res = SECFailure;
        return res;
    }

    if (key->publicValue.data[0] != EC_POINT_FORM_UNCOMPRESSED) {
        PORT_SetError(SEC_ERROR_UNSUPPORTED_EC_POINT_FORM);
        res = SECFailure;
        return res;
    }

    uint8_t hash[66] = { 0 };
    if (digest->len < 66) {
        memcpy(hash + 66 - digest->len, digest->data, digest->len);
    } else {
      // SEC 1 takes the most significant ceil(log(n)) bits of hash output when the hash output is longer than log(n).
        hash[0] = digest->data[0] >> 7;
	for (size_t i=1; i<66; i++) {
	hash[i] = (digest->data[i-1] << 1) | (digest->data[i] >> 7);
	}
    }
	  

    bool b = Hacl_P521_ecdsa_verif_without_hash(
        66, hash,
        key->publicValue.data + 1,
        signature->data, signature->data + 66);
    if (!b) {
        PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
        res = SECFailure;
        return res;
    }

    return res;
}
