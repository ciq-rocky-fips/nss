# SRC-GIT repository for the FIPS NSS.

The code is maintained in separate branches:

3.79-FIPS: Production FIPS nss for Rocky 8.
	Based on NSS-3.79.

3.90-FIPS: Production FIPS nss for Rocky 9.
	Based on NSS-3.90.

3.79-FIPS-FT: Functional test FIPS nss for Rocky 8.

	This code is only intended for funcitonal testing
	of the fips functionality and not to be used in production.
	This branch is a set of commits based ontop of 3.79-FIPS and is
	not supposed to be updated manually. Instead it should be rebased
	ontop of 3.79-FIPS anytime 3.79-FIPS changes.

3.90-FIPS-FT: Functional test FIPS nss for Rocky 9.

	This code is only intended for funcitonal testing
	of the fips functionality and not to be used in production.
	This branch is a set of commits based ontop of FIPS-3.7.6 and is
	not supposed to be updated manually. Instead it should be rebased
	ontop of 3.90-FIPS anytime 3.90-FIPS changes.

# To run the functional test scripts from the 3.79-FIPS-FT or 3.90-FIPS-FT branches.

# Build nss locally:
$ make_install.sh

# Run the functional tests:
- $ run_fipstest.sh
- $ tests/gtests/pct.sh
