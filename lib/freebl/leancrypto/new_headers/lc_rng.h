#ifndef LC_RNG_H
#define LC_RNG_H 1
#include <blapi.h>
#include <secrng.h>

struct lc_rng_ctx;
extern struct lc_rng_ctx *lc_seeded_rng;

/* just enough of the rng_context to make the code happy.
 * in the end, we just use our NSS internal RNG */
struct lc_static_rng_data {
    const unsigned char *seed;
    size_t seedlen;
};

struct lc_rng_ctx {
    struct lc_static_rng_data *dummy;
};

static inline int
lc_rng_generate(struct lc_rng_ctx *rng,
                unsigned char *addinput,
                size_t addlen,
                unsigned char *out,
                size_t outlen)
{
    size_t len;
    if (rng->dummy != NULL) {
        if (outlen > rng->dummy->seedlen) {
            return -1;
        }
        PORT_Memcpy(out, rng->dummy->seed, outlen);
        return 0;
    }
    if (addlen != 0) {
        RNG_RandomUpdate(addinput, addlen);
    }
    len = RNG_SystemRNG(out, outlen);
    if (len != outlen) {
        return -1;
    }
    return 0;
}

#define lc_rng_seed(rng, seed, seedlen, pers, perslen) \
    {                                                  \
        if (pers_len != 0) {                           \
            RNG_RandomUpdate(pers, perslen);           \
        }                                              \
        RNG_SystemRNG(seed, seedlen);                  \
    }
#define lc_rng_check(rng)

#define LC_STATIC_DRNG_ON_STACK(sdrng, state) \
    struct lc_rng_ctx sdrng;                  \
    sdrng.dummy = state;

#endif
