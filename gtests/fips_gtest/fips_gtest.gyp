# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
{
  'includes': [
    '../../coreconf/config.gypi',
    '../common/gtest.gypi',
  ],
  'targets': [    
    {
      'target_name': 'fips_gtest',
      'type': 'executable',
      'sources': [
        'fips_test.cc',        
        '<(DEPTH)/gtests/common/gtests.cc'
      ],
      'dependencies': [
        '<(DEPTH)/exports.gyp:nss_exports',
        '<(DEPTH)/cpputil/cpputil.gyp:cpputil',
        '<(DEPTH)/gtests/google_test/google_test.gyp:gtest',
        '<(DEPTH)/lib/util/util.gyp:nssutil3',
      ],
      'conditions': [
        [ 'static_libs==1', {
          'dependencies': [
            '<(DEPTH)/lib/base/base.gyp:nssb',
            '<(DEPTH)/lib/certdb/certdb.gyp:certdb',
            '<(DEPTH)/lib/certhigh/certhigh.gyp:certhi',
            '<(DEPTH)/lib/cryptohi/cryptohi.gyp:cryptohi',
            '<(DEPTH)/lib/dev/dev.gyp:nssdev',
            '<(DEPTH)/lib/nss/nss.gyp:nss_static',
            '<(DEPTH)/lib/pk11wrap/pk11wrap.gyp:pk11wrap_static',
            '<(DEPTH)/lib/pki/pki.gyp:nsspki',
            '<(DEPTH)/lib/ssl/ssl.gyp:ssl',
            '<(DEPTH)/lib/libpkix/libpkix.gyp:libpkix',
          ],
        }, {
          'dependencies': [
            '<(DEPTH)/lib/nss/nss.gyp:nss3',
            '<(DEPTH)/lib/ssl/ssl.gyp:ssl3',
          ],
        }],
      ],
    }
  ],
  'target_defaults': {
    'defines': [
      'DLL_PREFIX=\"<(dll_prefix)\"',
      'DLL_SUFFIX=\"<(dll_suffix)\"'
    ]
  },
  'variables': {
    'module': 'nss'
  }
}