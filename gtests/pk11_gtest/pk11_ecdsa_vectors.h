/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

namespace nss_test {

// ECDSA test vector, A.2.5. ECDSA, 256 Bits (Prime Field), SHA-256
// <https://tools.ietf.org/html/rfc6979#appendix-A.2.5>
const uint8_t kP256Pkcs8[] = {
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57,
    0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
    0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61,
    0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61,
    0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03,
    0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28,
    0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3,
    0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
const uint8_t kP256Spki[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9,
    0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b,
    0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79,
    0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56,
    0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77,
    0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
const uint8_t kP256Data[] = {'s', 'a', 'm', 'p', 'l', 'e'};
const uint8_t kP256Signature[] = {
    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd,
    0x9c, 0xd4, 0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa,
    0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16, 0xf7,
    0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1,
    0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4,
    0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8};

// ECDSA test vector, A.2.6. ECDSA, 384 Bits (Prime Field), SHA-384
// <https://tools.ietf.org/html/rfc6979#appendix-A.2.6>
const uint8_t kP384Pkcs8[] = {
    0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
    0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01, 0x01, 0x04, 0x30, 0x6b,
    0x9d, 0x3d, 0xad, 0x2e, 0x1b, 0x8c, 0x1c, 0x05, 0xb1, 0x98, 0x75, 0xb6,
    0x65, 0x9f, 0x4d, 0xe2, 0x3c, 0x3b, 0x66, 0x7b, 0xf2, 0x97, 0xba, 0x9a,
    0xa4, 0x77, 0x40, 0x78, 0x71, 0x37, 0xd8, 0x96, 0xd5, 0x72, 0x4e, 0x4c,
    0x70, 0xa8, 0x25, 0xf8, 0x72, 0xc9, 0xea, 0x60, 0xd2, 0xed, 0xf5, 0xa1,
    0x64, 0x03, 0x62, 0x00, 0x04, 0xec, 0x3a, 0x4e, 0x41, 0x5b, 0x4e, 0x19,
    0xa4, 0x56, 0x86, 0x18, 0x02, 0x9f, 0x42, 0x7f, 0xa5, 0xda, 0x9a, 0x8b,
    0xc4, 0xae, 0x92, 0xe0, 0x2e, 0x06, 0xaa, 0xe5, 0x28, 0x6b, 0x30, 0x0c,
    0x64, 0xde, 0xf8, 0xf0, 0xea, 0x90, 0x55, 0x86, 0x60, 0x64, 0xa2, 0x54,
    0x51, 0x54, 0x80, 0xbc, 0x13, 0x80, 0x15, 0xd9, 0xb7, 0x2d, 0x7d, 0x57,
    0x24, 0x4e, 0xa8, 0xef, 0x9a, 0xc0, 0xc6, 0x21, 0x89, 0x67, 0x08, 0xa5,
    0x93, 0x67, 0xf9, 0xdf, 0xb9, 0xf5, 0x4c, 0xa8, 0x4b, 0x3f, 0x1c, 0x9d,
    0xb1, 0x28, 0x8b, 0x23, 0x1c, 0x3a, 0xe0, 0xd4, 0xfe, 0x73, 0x44, 0xfd,
    0x25, 0x33, 0x26, 0x47, 0x20};
const uint8_t kP384Spki[] = {
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
    0xec, 0x3a, 0x4e, 0x41, 0x5b, 0x4e, 0x19, 0xa4, 0x56, 0x86, 0x18, 0x02,
    0x9f, 0x42, 0x7f, 0xa5, 0xda, 0x9a, 0x8b, 0xc4, 0xae, 0x92, 0xe0, 0x2e,
    0x06, 0xaa, 0xe5, 0x28, 0x6b, 0x30, 0x0c, 0x64, 0xde, 0xf8, 0xf0, 0xea,
    0x90, 0x55, 0x86, 0x60, 0x64, 0xa2, 0x54, 0x51, 0x54, 0x80, 0xbc, 0x13,
    0x80, 0x15, 0xd9, 0xb7, 0x2d, 0x7d, 0x57, 0x24, 0x4e, 0xa8, 0xef, 0x9a,
    0xc0, 0xc6, 0x21, 0x89, 0x67, 0x08, 0xa5, 0x93, 0x67, 0xf9, 0xdf, 0xb9,
    0xf5, 0x4c, 0xa8, 0x4b, 0x3f, 0x1c, 0x9d, 0xb1, 0x28, 0x8b, 0x23, 0x1c,
    0x3a, 0xe0, 0xd4, 0xfe, 0x73, 0x44, 0xfd, 0x25, 0x33, 0x26, 0x47, 0x20};
const uint8_t kP384Data[] = {'s', 'a', 'm', 'p', 'l', 'e'};
const uint8_t kP384Signature[] = {
    0x94, 0xed, 0xbb, 0x92, 0xa5, 0xec, 0xb8, 0xaa, 0xd4, 0x73, 0x6e, 0x56,
    0xc6, 0x91, 0x91, 0x6b, 0x3f, 0x88, 0x14, 0x06, 0x66, 0xce, 0x9f, 0xa7,
    0x3d, 0x64, 0xc4, 0xea, 0x95, 0xad, 0x13, 0x3c, 0x81, 0xa6, 0x48, 0x15,
    0x2e, 0x44, 0xac, 0xf9, 0x6e, 0x36, 0xdd, 0x1e, 0x80, 0xfa, 0xbe, 0x46,
    0x99, 0xef, 0x4a, 0xeb, 0x15, 0xf1, 0x78, 0xce, 0xa1, 0xfe, 0x40, 0xdb,
    0x26, 0x03, 0x13, 0x8f, 0x13, 0x0e, 0x74, 0x0a, 0x19, 0x62, 0x45, 0x26,
    0x20, 0x3b, 0x63, 0x51, 0xd0, 0xa3, 0xa9, 0x4f, 0xa3, 0x29, 0xc1, 0x45,
    0x78, 0x6e, 0x67, 0x9e, 0x7b, 0x82, 0xc7, 0x1a, 0x38, 0x62, 0x8a, 0xc8};

// ECDSA test vector, A.2.7. ECDSA, 521 Bits (Prime Field), SHA-512
// <https://tools.ietf.org/html/rfc6979#appendix-A.2.7>
const uint8_t kP521Pkcs8[] = {
    0x30, 0x81, 0xed, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
    0x04, 0x81, 0xd5, 0x30, 0x81, 0xd2, 0x02, 0x01, 0x01, 0x04, 0x42, 0x00,
    0xfa, 0xd0, 0x6d, 0xaa, 0x62, 0xba, 0x3b, 0x25, 0xd2, 0xfb, 0x40, 0x13,
    0x3d, 0xa7, 0x57, 0x20, 0x5d, 0xe6, 0x7f, 0x5b, 0xb0, 0x01, 0x8f, 0xee,
    0x8c, 0x86, 0xe1, 0xb6, 0x8c, 0x7e, 0x75, 0xca, 0xa8, 0x96, 0xeb, 0x32,
    0xf1, 0xf4, 0x7c, 0x70, 0x85, 0x58, 0x36, 0xa6, 0xd1, 0x6f, 0xcc, 0x14,
    0x66, 0xf6, 0xd8, 0xfb, 0xec, 0x67, 0xdb, 0x89, 0xec, 0x0c, 0x08, 0xb0,
    0xe9, 0x96, 0xb8, 0x35, 0x38, 0xa1, 0x81, 0x88, 0x03, 0x81, 0x85, 0x00,
    0x04, 0x18, 0x94, 0x55, 0x0d, 0x07, 0x85, 0x93, 0x2e, 0x00, 0xea, 0xa2,
    0x3b, 0x69, 0x4f, 0x21, 0x3f, 0x8c, 0x31, 0x21, 0xf8, 0x6d, 0xc9, 0x7a,
    0x04, 0xe5, 0xa7, 0x16, 0x7d, 0xb4, 0xe5, 0xbc, 0xd3, 0x71, 0x12, 0x3d,
    0x46, 0xe4, 0x5d, 0xb6, 0xb5, 0xd5, 0x37, 0x0a, 0x7f, 0x20, 0xfb, 0x63,
    0x31, 0x55, 0xd3, 0x8f, 0xfa, 0x16, 0xd2, 0xbd, 0x76, 0x1d, 0xca, 0xc4,
    0x74, 0xb9, 0xa2, 0xf5, 0x02, 0x3a, 0x40, 0x49, 0x31, 0x01, 0xc9, 0x62,
    0xcd, 0x4d, 0x2f, 0xdd, 0xf7, 0x82, 0x28, 0x5e, 0x64, 0x58, 0x41, 0x39,
    0xc2, 0xf9, 0x1b, 0x47, 0xf8, 0x7f, 0xf8, 0x23, 0x54, 0xd6, 0x63, 0x0f,
    0x74, 0x6a, 0x28, 0xa0, 0xdb, 0x25, 0x74, 0x1b, 0x5b, 0x34, 0xa8, 0x28,
    0x00, 0x8b, 0x22, 0xac, 0xc2, 0x3f, 0x92, 0x4f, 0xaa, 0xfb, 0xd4, 0xd3,
    0x3f, 0x81, 0xea, 0x66, 0x95, 0x6d, 0xfe, 0xaa, 0x2b, 0xfd, 0xfc, 0xf5};
const uint8_t kP521Spki[] = {
    0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86,
    0x00, 0x04, 0x01, 0x89, 0x45, 0x50, 0xd0, 0x78, 0x59, 0x32, 0xe0, 0x0e,
    0xaa, 0x23, 0xb6, 0x94, 0xf2, 0x13, 0xf8, 0xc3, 0x12, 0x1f, 0x86, 0xdc,
    0x97, 0xa0, 0x4e, 0x5a, 0x71, 0x67, 0xdb, 0x4e, 0x5b, 0xcd, 0x37, 0x11,
    0x23, 0xd4, 0x6e, 0x45, 0xdb, 0x6b, 0x5d, 0x53, 0x70, 0xa7, 0xf2, 0x0f,
    0xb6, 0x33, 0x15, 0x5d, 0x38, 0xff, 0xa1, 0x6d, 0x2b, 0xd7, 0x61, 0xdc,
    0xac, 0x47, 0x4b, 0x9a, 0x2f, 0x50, 0x23, 0xa4, 0x00, 0x49, 0x31, 0x01,
    0xc9, 0x62, 0xcd, 0x4d, 0x2f, 0xdd, 0xf7, 0x82, 0x28, 0x5e, 0x64, 0x58,
    0x41, 0x39, 0xc2, 0xf9, 0x1b, 0x47, 0xf8, 0x7f, 0xf8, 0x23, 0x54, 0xd6,
    0x63, 0x0f, 0x74, 0x6a, 0x28, 0xa0, 0xdb, 0x25, 0x74, 0x1b, 0x5b, 0x34,
    0xa8, 0x28, 0x00, 0x8b, 0x22, 0xac, 0xc2, 0x3f, 0x92, 0x4f, 0xaa, 0xfb,
    0xd4, 0xd3, 0x3f, 0x81, 0xea, 0x66, 0x95, 0x6d, 0xfe, 0xaa, 0x2b, 0xfd,
    0xfc, 0xf5};
const uint8_t kP521Data[] = {'s', 'a', 'm', 'p', 'l', 'e'};
const uint8_t kP521Signature[] = {
    0x00, 0xc3, 0x28, 0xfa, 0xfc, 0xbd, 0x79, 0xdd, 0x77, 0x85, 0x03, 0x70,
    0xc4, 0x63, 0x25, 0xd9, 0x87, 0xcb, 0x52, 0x55, 0x69, 0xfb, 0x63, 0xc5,
    0xd3, 0xbc, 0x53, 0x95, 0x0e, 0x6d, 0x4c, 0x5f, 0x17, 0x4e, 0x25, 0xa1,
    0xee, 0x90, 0x17, 0xb5, 0xd4, 0x50, 0x60, 0x6a, 0xdd, 0x15, 0x2b, 0x53,
    0x49, 0x31, 0xd7, 0xd4, 0xe8, 0x45, 0x5c, 0xc9, 0x1f, 0x9b, 0x15, 0xbf,
    0x05, 0xec, 0x36, 0xe3, 0x77, 0xfa, 0x00, 0x61, 0x7c, 0xce, 0x7c, 0xf5,
    0x06, 0x48, 0x06, 0xc4, 0x67, 0xf6, 0x78, 0xd3, 0xb4, 0x08, 0x0d, 0x6f,
    0x1c, 0xc5, 0x0a, 0xf2, 0x6c, 0xa2, 0x09, 0x41, 0x73, 0x08, 0x28, 0x1b,
    0x68, 0xaf, 0x28, 0x26, 0x23, 0xea, 0xa6, 0x3e, 0x5b, 0x5c, 0x07, 0x23,
    0xd8, 0xb8, 0xc3, 0x7f, 0xf0, 0x77, 0x7b, 0x1a, 0x20, 0xf8, 0xcc, 0xb1,
    0xdc, 0xcc, 0x43, 0x99, 0x7f, 0x1e, 0xe0, 0xe4, 0x4d, 0xa4, 0xa6, 0x7a};

// ECDSA P256 test case with a leading zero in the private key
const uint8_t kP256Pkcs8ZeroPad[] = {
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    0x00, 0x16, 0x40, 0x71, 0x99, 0xe3, 0x07, 0xaa, 0xdc, 0x98, 0x0b, 0x21,
    0x62, 0xce, 0x66, 0x1f, 0xe4, 0x1a, 0x86, 0x9a, 0x23, 0x33, 0xf6, 0x72,
    0xb4, 0xa3, 0xdc, 0x3b, 0x50, 0xba, 0x20, 0xce, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0x53, 0x11, 0x9a, 0x86, 0xa0, 0xc2, 0x99, 0x4f, 0xa6, 0xf8,
    0x08, 0xf8, 0x61, 0x01, 0x0e, 0x6b, 0x04, 0x9c, 0xd8, 0x15, 0x63, 0x2e,
    0xd1, 0x38, 0x00, 0x10, 0xee, 0xe4, 0xc9, 0x11, 0xff, 0x05, 0xba, 0xd6,
    0xcd, 0x94, 0xea, 0x00, 0xec, 0x85, 0x26, 0x2c, 0xbd, 0x4d, 0x85, 0xbd,
    0x20, 0xce, 0xa5, 0xb1, 0x3f, 0x4d, 0x82, 0x9b, 0x9f, 0x28, 0x2e, 0xd3,
    0x8a, 0x87, 0x1f, 0x89, 0xf8, 0x02};
const uint8_t kP256SpkiZeroPad[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0x53, 0x11, 0x9a, 0x86, 0xa0, 0xc2, 0x99, 0x4f, 0xa6,
    0xf8, 0x08, 0xf8, 0x61, 0x01, 0x0e, 0x6b, 0x04, 0x9c, 0xd8, 0x15, 0x63,
    0x2e, 0xd1, 0x38, 0x00, 0x10, 0xee, 0xe4, 0xc9, 0x11, 0xff, 0x05, 0xba,
    0xd6, 0xcd, 0x94, 0xea, 0x00, 0xec, 0x85, 0x26, 0x2c, 0xbd, 0x4d, 0x85,
    0xbd, 0x20, 0xce, 0xa5, 0xb1, 0x3f, 0x4d, 0x82, 0x9b, 0x9f, 0x28, 0x2e,
    0xd3, 0x8a, 0x87, 0x1f, 0x89, 0xf8, 0x02};
const uint8_t kP256DataZeroPad[] = {'s', 'a', 'm', 'p', 'l', 'e'};
const uint8_t kP256SignatureZeroPad[] = {
    0xa6, 0xf4, 0xe4, 0xa8, 0x3f, 0x03, 0x59, 0x89, 0x60, 0x53, 0xe7,
    0xdc, 0xb5, 0xbe, 0x78, 0xaf, 0xc1, 0xca, 0xc0, 0x65, 0xba, 0xa4,
    0x3c, 0xf1, 0xe4, 0xae, 0xe3, 0xba, 0x22, 0x3d, 0xac, 0x9d, 0x6d,
    0x1b, 0x26, 0x00, 0xcf, 0x47, 0xa1, 0xe1, 0x04, 0x21, 0x8d, 0x0b,
    0xbb, 0x16, 0xfa, 0x3e, 0x59, 0x32, 0x01, 0xb0, 0x45, 0x3e, 0x27,
    0xa4, 0xc4, 0xfd, 0x31, 0xc9, 0x1a, 0x8e, 0x74, 0xd8};

// ECDSA test vectors, SPKI and PKCS#8 edge cases.
const uint8_t kP256Pkcs8NoCurveOIDOrAlgorithmParams[] = {
    0x30, 0x7d, 0x02, 0x01, 0x00, 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04,
    0x20, 0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
    0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b,
    0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21, 0xa1, 0x44, 0x03,
    0x42, 0x00, 0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9,
    0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b,
    0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79,
    0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56,
    0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77,
    0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
const uint8_t kP256Pkcs8OnlyAlgorithmParams[] = {
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57,
    0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
    0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61,
    0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61,
    0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03,
    0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28,
    0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3,
    0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
const uint8_t kP256Pkcs8NoAlgorithmParams[] = {
    0x30, 0x81, 0x89, 0x02, 0x01, 0x00, 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x04, 0x79, 0x30, 0x77, 0x02, 0x01, 0x01,
    0x04, 0x20, 0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c,
    0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
    0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21, 0xa0, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44,
    0x03, 0x42, 0x00, 0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31,
    0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92,
    0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
    0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9,
    0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51,
    0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
const uint8_t kP256Pkcs8MatchingCurveOIDAndAlgorithmParams[] = {
    0x30, 0x81, 0x93, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x79, 0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20,
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57,
    0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
    0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21, 0xa0, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61,
    0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61,
    0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03,
    0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28,
    0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3,
    0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
const uint8_t kP256Pkcs8DissimilarCurveOIDAndAlgorithmParams[] = {
    0x30, 0x81, 0x90, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x76, 0x30, 0x74, 0x02, 0x01, 0x01, 0x04, 0x20,
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57,
    0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
    0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21, 0xa0, 0x07, 0x06, 0x05,
    0x2b, 0x81, 0x04, 0x00, 0x22, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x60,
    0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6,
    0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6,
    0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08,
    0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64, 0xf2,
    0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4,
    0x46, 0x22, 0x99};
const uint8_t kP256Pkcs8InvalidAlgorithmParams[] = {
    0x30, 0x81, 0x82, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x04, 0x6d,
    0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0xc9, 0xaf, 0xa9, 0xd8, 0x45,
    0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e,
    0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12,
    0x0f, 0x67, 0x21, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x60, 0xfe, 0xd4,
    0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d,
    0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62,
    0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc,
    0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2,
    0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22,
    0x99};
const uint8_t kP256Pkcs8PointNotOnCurve[] = {
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57,
    0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
    0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61,
    0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61,
    0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03,
    0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28,
    0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3,
    0xc2, 0x94, 0xd4, 0x33, 0x11, 0x77};
const uint8_t kP256Pkcs8NoPublicKey[] = {
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
    0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20, 0xc9,
    0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67,
    0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b,
    0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};
const uint8_t kP256SpkiNoAlgorithmParams[] = {
    0x30, 0x4f, 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x03, 0x42, 0x00, 0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d,
    0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8,
    0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f,
    0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9,
    0xe9, 0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f,
    0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
const uint8_t kP256SpkiPointNotOnCurve[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9,
    0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b,
    0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79,
    0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56,
    0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77,
    0xa3, 0xc2, 0x94, 0x00, 0x33, 0x11, 0x77};

const uint8_t kP521DataUnpaddedSigLong[] = {'W', 'T', 'F', '6', '0', 'M', 'W', 'M', 'N', '3'};
const uint8_t kP521DataUnpaddedSigShort[] = { 'M', 'I', '6', '3', 'V', 'N', 'G', 'L', 'F', 'R',};
const uint8_t kP521SpkiUnpaddedSig[] = {
    0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86,
    0x00, 0x04, 0x01, 0xd2, 0x37, 0xeb, 0x78, 0xc7, 0x9b, 0x86, 0xff, 0x29,
    0x7b, 0x55, 0x4d, 0x11, 0xc7, 0x9c, 0x2d, 0xc1, 0x67, 0x9f, 0xad, 0x2a,
    0xa9, 0xb9, 0x51, 0x30, 0x6d, 0xde, 0x14, 0x16, 0xea, 0xb3, 0x9d, 0x18,
    0xfc, 0xf0, 0x38, 0x6e, 0x7f, 0xa6, 0x82, 0xb9, 0x19, 0x01, 0xaf, 0xe7,
    0xc3, 0xd8, 0xec, 0x9a, 0x62, 0x7b, 0xbf, 0x41, 0xc7, 0x86, 0x89, 0x52,
    0x76, 0x8e, 0x01, 0x97, 0x1b, 0x16, 0x97, 0x69, 0x01, 0x2d, 0x07, 0x88,
    0x6f, 0xe0, 0x17, 0xbe, 0x82, 0xc4, 0x12, 0xd6, 0x16, 0x72, 0xf8, 0x57,
    0x75, 0x5c, 0x69, 0x79, 0xd0, 0x11, 0x05, 0x96, 0x2f, 0xa4, 0x61, 0xcd,
    0x8f, 0x54, 0x95, 0x58, 0xbd, 0x7d, 0x71, 0x84, 0x63, 0x18, 0xb8, 0x5b,
    0xaa, 0x1b, 0xd2, 0xe9, 0x65, 0x63, 0x15, 0x34, 0x25, 0x35, 0x2f, 0x35,
    0x27, 0x3a, 0x84, 0x42, 0x7a, 0x42, 0x8e, 0xfd, 0x15, 0xbe, 0x0c, 0x0c,
    0xe2, 0x9f};
const uint8_t kP521SignatureUnpaddedSigLong[] = {
    0x01, 0xa7, 0x3a, 0x14, 0x79, 0x77, 0x9e, 0x48, 0xb0, 0xff, 0xb5, 0xbe,
    0xfb, 0xfa, 0x7a, 0x84, 0x24, 0xb3, 0x5c, 0xf0, 0xfd, 0x77, 0x9d, 0xd4,
    0x66, 0x49, 0xfd, 0xbf, 0x04, 0xbf, 0xbb, 0x75, 0x22, 0xbb, 0x35, 0x42,
    0xdb, 0xe7, 0xed, 0x5a, 0x8f, 0x15, 0xf3, 0xa9, 0x0e, 0xb6, 0x5b, 0xde,
    0x23, 0x79, 0x47, 0xa7, 0x1d, 0x25, 0x24, 0x68, 0x63, 0xf6, 0x9c, 0x2e,
    0x21, 0xe0, 0x30, 0xfc, 0xd3, 0x65, 0x01, 0x12, 0x4e, 0xf0, 0xbb, 0x89,
    0xec, 0xec, 0x4f, 0xef, 0xbe, 0xdc, 0xd6, 0xac, 0xa4, 0x16, 0x68, 0x2b,
    0x78, 0xdf, 0x6c, 0x6e, 0xb8, 0xf4, 0x5b, 0x45, 0x1b, 0xdd, 0x84, 0x40,
    0x94, 0x07, 0xc7, 0xbc, 0xb6, 0x57, 0x92, 0xf1, 0x64, 0xb9, 0x2c, 0xcb,
    0x1d, 0xbe, 0x1c, 0x93, 0x78, 0x97, 0x8b, 0x84, 0x4e, 0x69, 0x6d, 0x0b,
    0xb0, 0x5f, 0xf1, 0x84, 0x18, 0x82, 0x8d, 0x55, 0xdf, 0x36, 0x43, 0x8a};
const uint8_t kP521SignatureUnpaddedSigShort[] = {
    0x40, 0x12, 0xa7, 0x96, 0x5d, 0x77, 0xba, 0x8a, 0x90, 0x57, 0x52, 0x11,
    0xad, 0x72, 0x21, 0xd6, 0x6c, 0x73, 0x81, 0x43, 0x5d, 0x09, 0xe4, 0xde,
    0xee, 0xc2, 0xb5, 0x03, 0x1f, 0x0f, 0xd1, 0x6a, 0xfc, 0x26, 0x6d, 0x99,
    0x6d, 0x84, 0x32, 0x05, 0x56, 0x66, 0xe3, 0x6b, 0xf7, 0xf2, 0x04, 0xc9,
    0x44, 0x17, 0xaa, 0xbd, 0x24, 0xd8, 0x87, 0x4e, 0x53, 0x9d, 0x08, 0x65,
    0x91, 0x95, 0xeb, 0xeb, 0x92, 0x0b, 0xdb, 0x34, 0x80, 0xe8, 0x9f, 0x38,
    0x73, 0x00, 0x7c, 0xfc, 0x2b, 0xfa, 0xcf, 0xa6, 0x6c, 0x1c, 0xb0, 0x75,
    0x76, 0x01, 0x22, 0xe7, 0x3c, 0xd8, 0xc4, 0x1f, 0x5e, 0xde, 0x0b, 0x95,
    0x7a, 0x50, 0x2b, 0x8c, 0x87, 0xc4, 0x12, 0x8e, 0x00, 0x09, 0x29, 0x2c,
    0x21, 0xd1, 0x96, 0xa0, 0xf3, 0x0f, 0x54, 0xdb, 0x6a, 0xbb, 0x90, 0xf5,
    0x5c, 0x7a, 0x8d, 0x83, 0x9c, 0x39, 0x38, 0x58, 0x5a, 0x0e};
const uint8_t kP384DataUnpaddedSigLong[] = {'L', 'T', 'N', '4', 'B', 'P', 'X', 'Y', '5', 'N'};
const uint8_t kP384DataUnpaddedSigShort[] = {'3', 'U', 'S', 'N', 'N', 'U', '6', 'E', 'E', '0'};
const uint8_t kP384SpkiUnpaddedSig[] = {
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
    0x1e, 0x98, 0x4c, 0xcf, 0x05, 0xd4, 0x9b, 0x98, 0x11, 0xae, 0xa1, 0xaa,
    0x72, 0x27, 0xac, 0xde, 0x7f, 0xe8, 0x4d, 0xda, 0xaa, 0x67, 0x51, 0x2e,
    0x0b, 0x30, 0x31, 0xab, 0x05, 0xac, 0x95, 0xdf, 0x09, 0x96, 0xcf, 0xe3,
    0xf5, 0xfa, 0x30, 0xad, 0x43, 0x0b, 0xa5, 0x7e, 0xd7, 0xd1, 0xee, 0x4e,
    0x83, 0x53, 0xe3, 0x26, 0xeb, 0xc1, 0xc9, 0xe5, 0x35, 0x36, 0x1a, 0xbf,
    0xbf, 0x99, 0xd6, 0xe2, 0x14, 0x43, 0xcb, 0x54, 0xde, 0x06, 0xb5, 0x7d,
    0x27, 0xb7, 0xc2, 0x27, 0xaf, 0xb6, 0x12, 0x4f, 0x47, 0xa0, 0xdb, 0xb5,
    0x6e, 0x7b, 0x44, 0x0d, 0xc8, 0xbd, 0x13, 0x3c, 0x27, 0x7c, 0xf2, 0x3a};
const uint8_t kP384SignatureUnpaddedSigLong[] = {
    0x19, 0x22, 0x21, 0x72, 0x8a, 0xa4, 0x22, 0x26, 0x75, 0x16, 0x9c, 0x58,
    0x93, 0xd8, 0x43, 0xac, 0x28, 0x78, 0xe7, 0xe2, 0xf2, 0x5d, 0xa6, 0x59,
    0x74, 0x6d, 0x55, 0x95, 0xe1, 0xa8, 0xc9, 0x18, 0x54, 0x5d, 0x03, 0xa0,
    0xb0, 0x90, 0xe9, 0xf1, 0xc5, 0xf6, 0x29, 0x1a, 0x50, 0x9d, 0xe3, 0xde,
    0x4a, 0x69, 0xdf, 0x1b, 0xe5, 0x53, 0xd7, 0xe8, 0xd4, 0xbf, 0x8c, 0xfc,
    0x07, 0x66, 0xbc, 0xa7, 0xb5, 0x47, 0x29, 0xbd, 0x15, 0x8c, 0x57, 0x6c,
    0xde, 0x37, 0x57, 0xa4, 0xd4, 0x61, 0x79, 0x92, 0x67, 0x25, 0x2e, 0xbc,
    0x8b, 0x88, 0x6a, 0xfa, 0xa5, 0x00, 0x19, 0x11, 0x64, 0x69, 0x7b, 0xf6};
const uint8_t kP384SignatureUnpaddedSigShort[] = {
    0x69, 0xe6, 0xc2, 0xd0, 0xb0, 0x59, 0xca, 0x1f, 0x07, 0x4c, 0x90, 0x13,
    0x75, 0xe0, 0xc5, 0xb9, 0x38, 0xf2, 0xd8, 0x55, 0xf7, 0x08, 0xbd, 0x8e,
    0x61, 0xbd, 0x50, 0x7e, 0xb6, 0xb5, 0xea, 0xbc, 0xa4, 0xa0, 0x18, 0x9b,
    0x63, 0x6b, 0x8a, 0x91, 0x88, 0x39, 0x0a, 0xbe, 0x6a, 0xb6, 0x4b, 0xaf,
    0xcb, 0x31, 0x89, 0xcf, 0x43, 0x28, 0x4b, 0x04, 0x6a, 0xe0, 0x8d, 0xbc,
    0xbf, 0xa2, 0x45, 0xdf, 0x1c, 0x83, 0x82, 0x3e, 0x2b, 0xa3, 0xea, 0x50,
    0x80, 0xec, 0x31, 0x48, 0x20, 0x30, 0x75, 0x94, 0xd9, 0x08, 0x9f, 0x6f,
    0x53, 0x21, 0x6f, 0x72, 0x74, 0x0c, 0xc4, 0x21, 0x28, 0xc9};
const uint8_t kP256DataUnpaddedSigLong[] = {'J', '5', 'C', 'N', 'Q', 'T', 'F', 'A', 'J', 'T'};
const uint8_t kP256DataUnpaddedSigShort[] = {'K', 'O', 'S', '9', '4', 'F', 'V', 'C', 'Y', 'C'};
const uint8_t kP256SpkiUnpaddedSig[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0x30, 0x40, 0x9d, 0x57, 0xdd, 0xd0, 0x70, 0x1d, 0x4b,
    0x40, 0x84, 0xd4, 0x7a, 0xc0, 0x30, 0x68, 0x33, 0xf1, 0x1d, 0x47, 0xaa,
    0x37, 0x4d, 0xe2, 0xc8, 0xce, 0xdc, 0x82, 0x1d, 0xf7, 0xcf, 0xdd, 0x9e,
    0xb6, 0x6c, 0x85, 0x87, 0x9d, 0x31, 0x79, 0x7e, 0xe4, 0xe9, 0xc7, 0x4f,
    0xd6, 0x07, 0x1d, 0x2f, 0x54, 0x82, 0x5d, 0x22, 0xbf, 0xbc, 0xf0, 0x75,
    0x01, 0x09, 0x43, 0xc6, 0x52, 0xcb, 0x45 };
const uint8_t kP256SignatureUnpaddedSigLong[] = {
    0xad, 0x6f, 0xcf, 0x41, 0xc1, 0x83, 0xe3, 0x6f, 0xe0, 0x2c, 0x9f, 0x56,
    0xa5, 0x17, 0x60, 0xbf, 0x80, 0x71, 0x18, 0x54, 0x1d, 0x82, 0xdb, 0xe6,
    0xc2, 0x4e, 0x60, 0x4a, 0xa6, 0x0c, 0xed, 0xcf, 0xe9, 0xbf, 0xda, 0x11,
    0xc2, 0x0a, 0x9c, 0x02, 0x5f, 0xb6, 0xa0, 0xb8, 0xbc, 0xda, 0xbf, 0x80,
    0xb4, 0xfb, 0x68, 0xab, 0xc8, 0xa8, 0x07, 0xeb, 0x50, 0x5c, 0x8a, 0x47,
    0xcf, 0x61, 0x91, 0x5f};
const uint8_t kP256SignatureUnpaddedSigShort[] = {
    0x3d, 0x99, 0x94, 0xa9, 0x80, 0x12, 0x43, 0x27, 0xde, 0x78, 0x9e, 0x61,
    0xaf, 0x10, 0xee, 0xd2, 0x22, 0xc6, 0x6e, 0x1c, 0xdf, 0xe7, 0x75, 0x28,
    0x84, 0xae, 0xb8, 0xdb, 0x7b, 0xf1, 0x91, 0x86, 0x5b, 0x5a, 0x28, 0x16,
    0x15, 0xfe, 0xd9, 0x48, 0x33, 0x95, 0xa8, 0x8f, 0x92, 0xbb, 0xe3, 0x9c,
    0xca, 0x04, 0xef, 0x56, 0x48, 0x16, 0x73, 0xa6, 0xb6, 0x6a, 0x38, 0xc9,
    0x78, 0xc4};
}  // namespace nss_test
