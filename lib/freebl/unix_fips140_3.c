/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/random.h>
#include <jitterentropy.h>

#include "secerr.h"
#include "secrng.h"
#include "prprf.h"
#include "prinit.h"

#ifndef GRND_RANDOM
PR_STATIC_ASSERT("You'll need to add our platform specific solution for FIPS 140-3 RNG" == NULL);
#endif

/* syscall getrandom() is limited to retrieving 256 bytes */
#define GETENTROPY_MAX_BYTES 256

/* Jitterentropy state (used only in FIPS mode) */
static struct rand_data *system_jitter;
static unsigned int jent_osr = 0;
static unsigned int jent_flags = 0;

static PRBool use_jitter = PR_FALSE;
static PRCallOnceType rng_KernelFips;

static PRStatus
rng_getKernelFips()
{
    if (NSS_GetSystemFIPSEnabled()) {
        use_jitter = PR_TRUE;
        jent_osr = 3;
        jent_flags = JENT_FORCE_FIPS;
    }
    return PR_SUCCESS;
}

void
RNG_SystemInfoForRNG(void)
{
    PRUint8 bytes[SYSTEM_RNG_SEED_COUNT];
    size_t numBytes = RNG_SystemRNG(bytes, SYSTEM_RNG_SEED_COUNT);
    if (!numBytes) {
        /* error is set */
        return;
    }
    RNG_RandomUpdate(bytes, numBytes);
    PORT_SafeZero(bytes, sizeof(bytes));
}

size_t
RNG_SystemRNG(void *dest, size_t maxLen)
{
    PR_CallOnce(&rng_KernelFips, rng_getKernelFips);

    if (use_jitter) {
        /* FIPS mode: use jitterentropy for SP 800-90B compliant entropy */
        ssize_t result;

        if (!system_jitter) {
            if (jent_entropy_init_ex(jent_osr, jent_flags)) {
                PORT_SetError(SEC_ERROR_NEED_RANDOM);
                return 0;
            }
            system_jitter = jent_entropy_collector_alloc(jent_osr, jent_flags);
            if (!system_jitter) {
                PORT_SetError(SEC_ERROR_NEED_RANDOM);
                return 0;
            }
        }

        result = jent_read_entropy_safe(&system_jitter, dest, maxLen);
        if (result < 0) {
            PORT_SetError(SEC_ERROR_NEED_RANDOM);
            return 0;
        }
        return maxLen;
    }

    /* Non-FIPS mode: use kernel getrandom() (urandom pool) */
    {
        size_t fileBytes = 0;
        unsigned char *buffer = dest;

        while (fileBytes < maxLen) {
            size_t getBytes = maxLen - fileBytes;
            if (getBytes > GETENTROPY_MAX_BYTES) {
                getBytes = GETENTROPY_MAX_BYTES;
            }
            ssize_t result = getrandom(buffer, getBytes, 0);
            if (result < 0) {
                break;
            }
            fileBytes += result;
            buffer += result;
        }
        if (fileBytes == maxLen) {
            return maxLen;
        }
        PORT_SetError(SEC_ERROR_NEED_RANDOM);
        return 0;
    }
}
