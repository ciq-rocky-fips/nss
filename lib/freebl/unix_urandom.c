/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "secerr.h"
#include "secrng.h"
#include "prprf.h"

/* syscall getentropy() is limited to retrieving 256 bytes */
#define GETENTROPY_MAX_BYTES 256

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
    PORT_SafeZero(bytes, sizeof bytes);
}

#ifdef NSS_FIPS_140_3
#include <sys/random.h>
#include "prinit.h"

static int rng_grndFlags= 0;
static PRCallOnceType rng_KernelFips;

static PRStatus
rng_getKernelFips()
{
#ifdef LINUX
    FILE *f;
    char d;
    size_t size;

    f = fopen("/proc/sys/crypto/fips_enabled", "r");
    if (!f)
        return PR_FAILURE;

    size = fread(&d, 1, 1, f);
    fclose(f);
    if (size != 1)
        return PR_SUCCESS;
    if (d != '1')
        return PR_SUCCESS;
    /* if the kernel is in FIPS mode, set the GRND_RANDOM flag */
    rng_grndFlags = GRND_RANDOM;
#endif /* LINUX */
    return PR_SUCCESS;
}
#endif

size_t
RNG_SystemRNG(void *dest, size_t maxLen)
{
    size_t fileBytes = 0;
    unsigned char *buffer = dest;
#ifndef NSS_FIPS_140_3
    int fd;
    int bytes;
#else
    PR_CallOnce(&rng_KernelFips, rng_getKernelFips);
#endif

#if defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD_version >= 1200000) || (defined(LINUX) && defined(__GLIBC__) && ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 25))))
    int result;
    while (fileBytes < maxLen) {
        size_t getBytes = maxLen - fileBytes;
        if (getBytes > GETENTROPY_MAX_BYTES) {
            getBytes = GETENTROPY_MAX_BYTES;
        }
#ifdef NSS_FIPS_140_3
        /* FIP 140-3 requires full kernel reseeding for chained entropy sources
         * so we need to use getrandom with GRND_RANDOM.
         * getrandom returns -1 on failure, otherwise returns
         * the number of bytes, which can be less than getBytes */
        result = getrandom(buffer, getBytes, rng_grndFlags);
        if (result < 0) {
            break;
        }
        fileBytes += result;
        buffer += result;
#else
        /* get entropy returns 0 on success and always return
         * getBytes on success */
        result = getentropy(buffer, getBytes);
        if (result == 0) { /* success */
            fileBytes += getBytes;
            buffer += getBytes;
        } else {
            break;
        }
#endif
    }
    if (fileBytes == maxLen) { /* success */
        return maxLen;
    }
#ifdef NSS_FIPS_140_3
    /* in FIPS 104-3 we don't fallback, just fail */
    PORT_SetError(SEC_ERROR_NEED_RANDOM);
    return 0;
#else
    /* If we failed with an error other than ENOSYS, it means the destination
     * buffer is not writeable. We don't need to try writing to it again. */
    if (errno != ENOSYS) {
        PORT_SetError(SEC_ERROR_NEED_RANDOM);
        return 0;
    }
#endif /*!NSS_FIPS_140_3 */
#endif /* platorm has getentropy */
#ifndef NSS_FIPS_140_3
    /* ENOSYS means the kernel doesn't support getentropy()/getrandom().
     * Reset the number of bytes to get and fall back to /dev/urandom. */
    fileBytes = 0;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        PORT_SetError(SEC_ERROR_NEED_RANDOM);
        return 0;
    }
    while (fileBytes < maxLen) {
        bytes = read(fd, buffer, maxLen - fileBytes);
        if (bytes <= 0) {
            break;
        }
        fileBytes += bytes;
        buffer += bytes;
    }
    (void)close(fd);
    if (fileBytes != maxLen) {
        PORT_SetError(SEC_ERROR_NEED_RANDOM);
        return 0;
    }
    return fileBytes;
#endif
}
