/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "seccomon.h"

#if defined(XP_UNIX) && defined(NSS_FIPS_140_3)
#include "unix_fips140_3.c"
#elif defined(XP_UNIX) && defined(SEED_ONLY_DEV_URANDOM)
#include "unix_urandom.c"
#elif defined(XP_UNIX)
#include "unix_rand.c"
#endif
#ifdef XP_WIN
#include "win_rand.c"
#endif

/*
** Release any process-global resources held by the system RNG.
**
** In FIPS mode (unix_fips140_3.c) RNG_SystemRNG() lazily allocates a
** jitterentropy collector in the file-static `system_jitter'.  Nothing
** else frees it, so without this the collector (and its locked memory)
** is leaked on every C_Finalize/C_Initialize cycle.  Clearing the
** pointer lets the next RNG_SystemRNG() lazily re-allocate when freebl
** is not actually unloaded.
**
** Other configurations hold no such state, so this is a no-op there.
*/
void
RNG_SystemRNGShutdown(void)
{
#if defined(XP_UNIX) && defined(NSS_FIPS_140_3)
    if (system_jitter) {
        jent_entropy_collector_free(system_jitter);
        system_jitter = NULL;
    }
#endif
}
