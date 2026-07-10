// SPDX-License-Identifier: MIT
// NSS SHA3 bindings for ML-DSA leancrypto

#ifndef LC_SHA3__H
#define LC_SHA3__H
#include <blapi.h>

#define LC_SHA3_SIZE_RATE(bits) ((1600 - 2 * bits) >> 3)

#define LC_SHAKE_128_SIZE_BLOCK LC_SHA3_SIZE_RATE(128)
#define LC_SHAKE_256_SIZE_BLOCK LC_SHA3_SIZE_RATE(256)

/*#define SHAKE128_RATE 168
#define shake128 SHAKE_128_HashBuf

#define SHAKE256_RATE SHA3_256_BLOCK_LENGTH
#define shake256 SHAKE_256_HashBuf */

#define LC_HASH_CTX_ON_STACK(name, type_) \
    struct lc_hash_ctx _##name ; \
    _##name.hash= type_; \
    _##name.buf= NULL; \
    _##name.stream = false; \
    _##name.u.ctx_ptr = NULL; \
    struct lc_hash_ctx *name= &_##name; 

#define LC_HASH_SET_CTX(name, type_) \
    name->hash= type_;  \
    name->stream = true; \
    name->u.ctx_ptr = NULL; \
    name->buf = NULL;

#define LC_SHAKE_256_CTX(name) \
    LC_HASH_SET_CTX(name, lc_shake256);

typedef enum {
    lc_shake128,
    lc_shake256,
} sha3Type;


/* sigh, we buffer eKEverything because we can't correctly do multiple 
 * finals correctly. In cases where we know we are not going to
 * do multiple finals, set the streaming bool */
struct lc_hash_ctx {
    sha3Type hash;
    bool stream;
    union {
        SHAKE_256Context *shake256_ctx;
        SHAKE_128Context *shake128_ctx;
        void *ctx_ptr;
    }u;
    size_t digestSize;
    size_t current_input;
    size_t current_output;
    unsigned char *buf;
    size_t buf_size;
    unsigned char buf_space[2048];
    unsigned char buf2_space[2048];
};

#define lc_xof(type, in, inlen, out, outlen) \
    switch(type) { \
        case lc_shake128: \
            SHAKE_128_HashBuf(out, outlen, in, inlen); \
            break; \
        case lc_shake256: \
            SHAKE_256_HashBuf(out, outlen, in, inlen); \
            break; \
        default: \
            assert(0); \
    }

static inline void
lc_hash_init(struct lc_hash_ctx *ptr) {
    if (ptr->stream) {
        /* if we already have a context, just reset it, This is
         * what the caller wanted, saving a destroy and create */
        if (ptr->u.ctx_ptr == NULL) {
            switch (ptr->hash) {
            case lc_shake128:
                ptr->u.shake128_ctx = SHAKE_128_NewContext();
                break;
            case lc_shake256:
                ptr->u.shake256_ctx = SHAKE_256_NewContext();
                break;
            }
        }
        switch (ptr->hash) {
            case lc_shake128:
                SHAKE_128_Begin(ptr->u.shake128_ctx);
                break;
            case lc_shake256:
                SHAKE_256_Begin(ptr->u.shake256_ctx);
                break;
        }
        return;
    }
    /* we can be called with an active buffer, do and implicit reset here
     * and free that buffer before we set up the next one */
    if (ptr->buf  &&  ptr->buf != ptr->buf_space) {
        memset(ptr->buf, 0, ptr->current_input);
        free(ptr->buf);
    }
    ptr->digestSize = 0;
    ptr->current_input = 0;
    ptr->current_output = 0;
    ptr->buf_size = sizeof(ptr->buf_space);
    ptr->buf = &ptr->buf_space[0];
}

static inline void
lc_hash_update(struct lc_hash_ctx *ptr, const unsigned char *input, size_t inLen)  {
    if (inLen ==0) { return; } /* why were we even called with a NULL buffer? */
    if (ptr->stream) {
        switch (ptr->hash) {
            case lc_shake128:
                SHAKE_128_Absorb(ptr->u.shake128_ctx, input, inLen);
                break;
            case lc_shake256:
                SHAKE_256_Absorb(ptr->u.shake256_ctx, input, inLen);
                break;
        }
        return;
    }
    if (ptr->current_input + inLen > ptr->buf_size) {
        int len = ptr->current_input + inLen + 2048;
        unsigned char *newBuf;
        if (ptr->buf_size == sizeof(ptr->buf_space)) {
            newBuf = calloc(1, len);
            if (newBuf) {
                memcpy(newBuf, ptr->buf, ptr->buf_size);
                memset(ptr->buf_space, 0, sizeof(ptr->buf_space));
            }
        } else {
            newBuf = reallocarray(ptr->buf, 1, len);
        }
        if (!newBuf) {
            return;
        }
        ptr->buf = newBuf;
        ptr->buf_size = len;
    }
    memcpy(ptr->buf + ptr->current_input, input, inLen);
    ptr->current_input+=inLen;
}

#define lc_hash_set_digestsize(ptr, len) ((ptr)->digestSize = (len))
static inline void
lc_hash_final(struct lc_hash_ctx *ptr, unsigned char *output) 
{
    size_t outLen= ptr->digestSize;
    if (ptr->stream) {
        switch (ptr->hash) {
            case lc_shake128:
                SHAKE_128_SqueezeEnd(ptr->u.shake128_ctx, output, outLen);
                break;
            case lc_shake256:
                SHAKE_256_SqueezeEnd(ptr->u.shake256_ctx, output, outLen);
                break;
        }
        return;
    }
    int len= ptr->current_output+outLen;
    if (ptr->current_output == 0) {
        lc_xof(ptr->hash, ptr->buf, ptr->current_input, output, outLen);
        ptr->current_output += outLen;
        return;
    }
    if (len > sizeof(ptr->buf2_space)) {
        unsigned char *newBuf = calloc(1,len);
        if (!newBuf) {
            memset(output, 0, outLen);
            return;
        }
        lc_xof(ptr->hash, ptr->buf, ptr->current_input, newBuf, len);
        memcpy(output, newBuf+ptr->current_output, outLen);
        memset(newBuf, 0, len);
        free(newBuf);
        ptr->current_output += outLen;
        return;
    }
    lc_xof(ptr->hash, ptr->buf, ptr->current_input, ptr->buf2_space, len);
    memcpy(output, &ptr->buf2_space[ptr->current_output], outLen);
    memset(ptr->buf2_space, 0,len);
    ptr->current_output += outLen;
    return;
}

static inline void lc_hash_zero(struct lc_hash_ctx *ptr) 
{
    if (ptr->stream) {
        if (ptr->u.ctx_ptr != NULL) {
            switch (ptr->hash) {
                case lc_shake128:
                    SHAKE_128_DestroyContext(ptr->u.shake128_ctx, PR_TRUE);
                    ptr->u.shake128_ctx = NULL;
                    break;
                case lc_shake256:
                    SHAKE_128_DestroyContext(ptr->u.shake256_ctx, PR_TRUE);
                    ptr->u.shake256_ctx = NULL;
                    break;
            }
        }
        return;
    }
    memset(ptr->buf2_space, 0, sizeof(ptr->buf2_space));
    memset(ptr->buf_space, 0, sizeof(ptr->buf_space));
    if (ptr->buf != ptr->buf_space) {
        memset(ptr->buf, 0, ptr->buf_size);
        free(ptr->buf);
        ptr->buf = NULL;
    }
    lc_hash_init(ptr);
}
#endif
