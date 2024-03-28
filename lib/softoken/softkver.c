/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Library identity and versioning */

#include "softkver.h"
#include  <stdio.h>
#include  <stdlib.h>
#include <string.h>
#include "blapi.h"

#if defined(DEBUG)
#define _DEBUG_STRING " (debug)"
#else
#define _DEBUG_STRING ""
#endif

/*
 * Version information
 */
const char __nss_softokn_version[] = "Version: NSS " SOFTOKEN_VERSION _DEBUG_STRING;

#define PR_FALSE 0
#define PR_TRUE 1

int fips_request_failure(const char* name, const char* subname)
{
	static int env_var_check_done = PR_FALSE;
	static int func_test = PR_FALSE;
	int cmp_len = 0;
	int subname_cmp_len = 0;
	const char *enames = NULL;
	const char *np;

	if (name == NULL && subname == NULL) {
		return PR_FALSE;
	}

	if (!env_var_check_done) {
		const char *e = getenv("NSS_FIPS_FUNC_TEST");
		if (e != NULL) {
            func_test = PR_TRUE;
		}
		env_var_check_done = PR_TRUE;
	}
	if (!func_test) {
		return PR_FALSE;
	}
	/*
	 * Here we know logging is enabled. Parse
	 * the NSS_FIPS_LOGGING_NAMES variable
	 * and log if the name matches. Names are
	 * separated by a ':' character. Subnames
	 * separated from names by a '.' character.
	 */
	enames = getenv("NSS_FIPS_FUNC_TEST_NAMES");
	if (enames == NULL) {
		return PR_FALSE;
	}
	if (!name) {
        return PR_TRUE;
    }
	cmp_len = strlen(name);
	if (subname != NULL) {
		subname_cmp_len = strlen(subname);
	}
	for (np = enames; np != NULL;) {
		while (*np == ':') {
			np++;
		}
		/* Does "name" match ? */
		if (strncasecmp(np, name, cmp_len)==0) {
			if (subname == NULL) {
				/* Move past "name." */
				np += cmp_len + 1;
				if (*np == ':' || *np == '\0') {
					return PR_TRUE;
				}
				/* Allow wildcard match for subname in env var. */
				if (*np == '*' && (np[1] == ':' || np[1] == '\0')) {
					return PR_TRUE;
				}
			} else {
				/* Look for .subname */
				if (np[cmp_len] != '.') {
					np = strchr(np, ':');
					continue;
				}
				/* Move past "name." */
				np += cmp_len + 1;
				/* Allow wildcard match for subname in env var. */
				if (*np == '*' && (np[1] == ':' || np[1] == '\0')) {
					return PR_TRUE;
				}
				if (strncasecmp(np, subname, subname_cmp_len) == 0) {
					if (np[subname_cmp_len] == ':' || np[subname_cmp_len] == '\0') {
						return PR_TRUE;
					}
				}
			}
		}
		np = strchr(np, ':');
	}
	return PR_FALSE;
}

int fips_request_failure_num(const char* name, int subnum)
{
    char subname[128];
    memset(subname, 0, sizeof(subname));
    sprintf(subname, "%d", subnum);
	FIPSLOG_INFO("[%s.%s]",name, subname);
    return fips_request_failure(name, subname);
}
