#include "hasht.h"
#include "blapit.h"
#include "lc_memset_secure.h" /* sigh the original included it,
                               * so some files expect it to be there already */
#include "lc_memory_support.h" 
/* sigh Stephen doesn seem to believe in typedef, so
 * just stuff our context pointer into a struct */
#define LC_SHA3_256_CTX_SIZE (SHA3_256_BLOCK_LENGTH)
#define LC_SHA3_STATE_SIZE_ALIGN(x) (x)

#define LC_SHA3_512_SIZE_DIGEST SHA3_512_LENGTH

#ifndef LC_HASH_COMMON_ALIGNMENT
#define LC_HASH_COMMON_ALIGNMENT 64
#endif


