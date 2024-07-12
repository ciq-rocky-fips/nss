export FREEBL_NO_DEPEND=1

# Must export FREEBL_LOWHASH=1 for nsslowhash.h so that it gets
# copied to dist and the rpm install phase can find it
# This due of the upstream changes to fix
# https://bugzilla.mozilla.org/show_bug.cgi?id=717906
export FREEBL_LOWHASH=1

# uncomment if the iquote patch is activated
export IN_TREE_FREEBL_HEADERS_FIRST=1

# FIPS related defines
export NSS_FORCE_FIPS=1
export NSS_FIPS_VERSION="%{name}\ %{version}-%{srpmhash}"
eval $(sed -n 's/^\(\(NAME\|VERSION_ID\)=.*\)/OS_\1/p' /etc/os-release | sed -e 's/ /\\ /g')
export FIPS_MODULE_OS="$OS_NAME\ ${OS_VERSION_ID%%.*}"
export NSS_FIPS_MODULE_ID="${FIPS_MODULE_OS}\ ${NSS_FIPS_VERSION}"
export NSS_FIPS_140_3=1
export NSS_ENABLE_FIPS_INDICATORS=1

# Enable compiler optimizations and disable debugging code
#export BUILD_OPT=1

#export BUILD_OPT=0
#
## Uncomment to disable optimizations
#RPM_OPT_FLAGS=`echo $RPM_OPT_FLAGS | sed -e 's/-O2/-O0/g'`
#export RPM_OPT_FLAGS

# Generate symbolic info for debuggers
export XCFLAGS=$RPM_OPT_FLAGS

export LDFLAGS=$RPM_LD_FLAGS

export DSO_LDFLAGS=$RPM_LD_FLAGS

export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1

export NSPR_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nspr | sed 's/-I//'`
export NSPR_LIB_DIR=%{_libdir}

export NSS_USE_SYSTEM_SQLITE=1

export NSS_ALLOW_SSLKEYLOGFILE=1

export NSS_SEED_ONLY_DEV_URANDOM=1

export USE_64=1
export USE_DEBUG_RTL=1
export NSS_STRICT_INTEGRITY=1


#make clean
make all


