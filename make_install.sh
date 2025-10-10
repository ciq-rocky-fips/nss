#!/bin/sh -x

export RPM_OPT_FLAGS="-g"
mkdir -p ../build
BUILD_DIR=$PWD
export LDFLAGS="$RPM_LD_FLAGS"
export CFLAGS="$RPM_OPT_FLAGS"
#
# Build NSS
#
# This package fails its testsuite with LTO.  Disable LTO for now
#%%global _lto_cflags %%{nil}

export FREEBL_NO_DEPEND=1
export NSS_DISABLE_KYBER=1
export NSS_ENABLE_ML_DSA=1

# Must export FREEBL_LOWHASH=1 for nsslowhash.h so that it gets
# copied to dist and the rpm install phase can find it
# This due of the upstream changes to fix
# https://bugzilla.mozilla.org/show_bug.cgi?id=717906
export FREEBL_LOWHASH=1

## uncomment if the iquote patch is activated
export IN_TREE_FREEBL_HEADERS_FIRST=1
#
## FIPS related defines
export NSS_FORCE_FIPS=1
export NSS_FIPS_VERSION="%{name}\ %{nss_version}-%{srpmhash}"
eval $(sed -n 's/^\(\(NAME\|VERSION_ID\)=.*\)/OS_\1/p' /etc/os-release | sed -e 's/ /\\ /g')
export FIPS_MODULE_OS="$OS_NAME\ ${OS_VERSION_ID%%.*}"
export NSS_FIPS_MODULE_ID="${FIPS_MODULE_OS}\ ${NSS_FIPS_VERSION}"
## remove when the infrastructure is fixed
export NSS_FIPS_140_3=1
export NSS_ENABLE_FIPS_INDICATORS=1
#
## Disable compiler optimizations and enable debugging code
export BUILD_OPT=0
#
## Generate symbolic info for debuggers
export XCFLAGS=$RPM_OPT_FLAGS
#
## Work around false-positive warnings with gcc 10:
## https://bugzilla.redhat.com/show_bug.cgi?id=1803029
#%ifarch s390x
#export XCFLAGS="$XCFLAGS -Wno-error=maybe-uninitialized"
#%endif
#
## Similarly, but for gcc-11
#export XCFLAGS="$XCFLAGS -Wno-array-parameter"
#
export DSO_LDFLAGS=$RPM_LD_FLAGS
#
export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1
#
export NSPR_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nspr | sed 's/-I//'`
export NSPR_LIB_DIR=%{_libdir}
#
export NSS_USE_SYSTEM_SQLITE=1
#
export NSS_ALLOW_SSLKEYLOGFILE=1
#
export NSS_SEED_ONLY_DEV_URANDOM=1
#
#%if %{with dbm}
#%else
#export NSS_DISABLE_DBM=1
#%endif
#
#%ifnarch noarch
#%if 0%{__isa_bits} == 64
export USE_64=1
#%endif
#%endif
#
## Set the policy file location
## if set NSS will always check for the policy file and load if it exists
export POLICY_FILE="nss.config"
## location of the policy file
export POLICY_PATH="/etc/crypto-policies/back-ends"
#

export MOZ_OPTIMIZE=0
export MOZ_DEBUG_SYMBOLS=1
export BUILD_OPT=0
export OPTIMIZER=0
export CFLAGS=-g

make clean
#%{__make} -C ./nss all
make all
#%{__make} -C ./nss latest
make latest
