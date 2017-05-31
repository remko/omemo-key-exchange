//////////////////////////////////////////////////////////////////////
// Sodium (Alice) keys
//////////////////////////////////////////////////////////////////////

unsigned char sodiumPublicIdentityKey[32] = { 0x49, 0x6F, 0xC0, 0x6E, 0x78, 0x54, 0x35, 0xC4, 0x8C, 0x04, 0x86, 0x0E, 0x09, 0x06, 0x09, 0x40, 0x86, 0xDA, 0xDB, 0x39, 0x36, 0xD5, 0x63, 0x12, 0xA0, 0xF6, 0x4D, 0x63, 0x2C, 0x34, 0xE0, 0x38 };
unsigned char sodiumPrivateIdentityKey[64] = { 0x4B, 0x2D, 0xAF, 0x67, 0x75, 0x72, 0x23, 0xC4, 0xF5, 0x7F, 0x92, 0x33, 0xA9, 0xE4, 0x12, 0x95, 0x12, 0x7E, 0x83, 0x5C, 0xB9, 0xAA, 0x37, 0xD2, 0x61, 0x91, 0x06, 0x3B, 0x25, 0xD0, 0x53, 0xFD, 0x49, 0x6F, 0xC0, 0x6E, 0x78, 0x54, 0x35, 0xC4, 0x8C, 0x04, 0x86, 0x0E, 0x09, 0x06, 0x09, 0x40, 0x86, 0xDA, 0xDB, 0x39, 0x36, 0xD5, 0x63, 0x12, 0xA0, 0xF6, 0x4D, 0x63, 0x2C, 0x34, 0xE0, 0x38 };

unsigned char sodiumPublicSignedPreKey[32] = {0x5A,0x9E,0x20,0x3B,0x93,0xEB,0x9A,0xF4,0xED,0x33,0x51,0x19,0x7F,0xB6,0xA7,0xBD,0x42,0xF1,0x03,0xA4,0xF2,0x38,0x1A,0xD9,0xC2,0x6A,0x12,0x0C,0x9C,0xD9,0x13,0x14};
unsigned char sodiumPublicSignedPreKeySignature[64] = { 0xd6, 0x6b, 0xab, 0x92, 0x4a, 0x07, 0xce, 0xdf, 0x1d, 0x39, 0x93, 0xe8, 0xf6, 0xe7, 0xe4, 0xcc, 0x18, 0xfd, 0xed, 0x07, 0xf8, 0x81, 0xc5, 0xe1, 0x8f, 0x72, 0x2e, 0x9d, 0xda, 0x9f, 0xda, 0x75, 0x78, 0xfe, 0x73, 0xfb, 0x3c, 0x30, 0xcf, 0x91, 0x1a, 0x85, 0xe2, 0xc9, 0xe5, 0xf6, 0x20, 0xf9, 0xf4, 0x61, 0x33, 0x63, 0x06, 0xe6, 0x15, 0x4f, 0x41, 0x54, 0x0a, 0xd1, 0xd5, 0xdf, 0xda, 0x09 };
unsigned char sodiumPrivateSignedPreKey[32] = {0x38,0x78,0xB5,0x23,0x28,0xDA,0x0E,0xD2,0x05,0x07,0x12,0x84,0xDD,0x64,0x36,0xFC,0xBB,0xE2,0x8D,0x8E,0x2A,0x57,0x6E,0x87,0xD4,0x71,0x9A,0x13,0x28,0x84,0x42,0x63};
unsigned char sodiumPublicOTPreKey[32] = { 0xC8,0x5E,0x1A,0x65,0x2B,0x67,0x25,0x14,0x52,0x98,0x3E,0x71,0x08,0x99,0xB7,0x8C,0x36,0xA7,0x3C,0xF4,0x4D,0xE8,0x98,0x6B,0x0C,0xEC,0x87,0x1A,0xDC,0x1B,0x77,0x41};
unsigned char sodiumPrivateOTPreKey[32] = { 0xB0,0x03,0xED,0x4E,0x2F,0x57,0xC0,0x0A,0xA2,0x2B,0xB7,0x77,0x3A,0xAE,0x56,0x06,0x50,0x31,0x08,0x24,0x18,0xEA,0x4D,0xFA,0x1F,0x59,0xD3,0x9B,0xE8,0x4E,0x09,0x62};
unsigned char sodiumPrivateEphemeralKey[32] = {0x60,0xBF,0x87,0x4E,0x80,0xD2,0x93,0xBE,0x69,0x3C,0xC2,0x9D,0x58,0x37,0x2D,0x79,0xDF,0x21,0x89,0x73,0xDE,0x24,0xF9,0x65,0x02,0xB5,0x95,0x5A,0x12,0x62,0x4C,0x40};
unsigned char sodiumPublicEphemeralKey[32] = { 0x98,0xF8,0x7B,0x59,0x97,0x49,0x98,0x4C,0xD4,0x05,0x5E,0x8D,0x40,0xE5,0x93,0xD0,0xF3,0xFB,0xE3,0xC6,0xE2,0x5A,0x3C,0xA7,0x10,0x87,0x89,0xEB,0x95,0x28,0xC9,0x75};


//////////////////////////////////////////////////////////////////////
// Signal (Bob) keys
//////////////////////////////////////////////////////////////////////

unsigned char signalPrivateCurveIdentityKey[32] = { 0x70, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x6a };
unsigned char signalPublicCurveIdentityKey[32] = { 0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a };
unsigned char signalPublicIdentityKey[32] = { 0x81,0x20,0xf2,0x99,0xc3,0x7a,0xe1,0xca,0x64,0xa1,0x79,0xf6,0x38,0xa6,0xc6,0xfa,0xfd,0xe9,0x68,0xf1,0xc3,0x37,0x05,0xe2,0x8c,0x41,0x3c,0x75,0x79,0xd9,0x88,0x4f };
unsigned char signalPublicSignedPreKey[32] = { 0xE4,0x67,0xD5,0xFF,0x8C,0x8B,0x68,0x60,0xE0,0xE1,0xBF,0x16,0xE6,0x87,0x4C,0x77,0x91,0x4E,0x55,0x75,0xA1,0xE8,0xA0,0x64,0xCB,0x34,0x2D,0x48,0x1A,0xF0,0xA7,0x2C };
unsigned char signalPublicSignedPreKeySignature[64] = { 0xf0,0x08,0xd7,0x9b,0xb6,0x71,0xb2,0x93,0xe1,0x02,0xc8,0x47,0xcf,0x79,0xe8,0x88,0x90,0xe5,0xe2,0x96,0x12,0xe9,0x79,0x18,0x7c,0x98,0x97,0x27,0x4c,0x82,0x52,0x0f,0x23,0x85,0x6d,0x74,0xee,0x45,0xb0,0x65,0xe3,0x1e,0xdd,0xd0,0xab,0x58,0x05,0x26,0x59,0xfb,0x55,0xba,0x11,0xfe,0x5a,0x0a,0x8b,0xd7,0x00,0x14,0x54,0x57,0x5f,0x09 };
unsigned char signalPrivateSignedPreKey[32] = { 0xF8,0xED,0xF2,0xEB,0x4D,0xEB,0x1E,0xC2,0xD4,0x41,0x68,0xB1,0x69,0x12,0xDC,0xF6,0x76,0x25,0x82,0x1D,0xF6,0x31,0x3E,0xC9,0x3F,0xA2,0x79,0xA2,0xC6,0x93,0x34,0x7C};
unsigned char signalPublicOTPreKey[32] = { 0xE2,0xD7,0x22,0x41,0x47,0xAD,0xA4,0x4E,0xDB,0xA9,0xD3,0x2F,0xAE,0xBB,0xF2,0x19,0x7B,0x65,0x79,0x02,0x8E,0x42,0x58,0x18,0x9C,0x0E,0x74,0x89,0xB3,0x11,0xDD,0x7A};
unsigned char signalPrivateOTPreKey[32] = { 0x10,0x2B,0x56,0x71,0xFE,0xFF,0x46,0x37,0x9F,0x9D,0x4A,0x82,0x95,0xF7,0x71,0xFB,0x06,0xFD,0xB7,0xC0,0xFB,0x06,0x7F,0x73,0x82,0x11,0x7E,0x89,0x2D,0xD2,0xAE,0x52};
unsigned char signalPrivateEphemeralKey[32] = { 0xD0,0x84,0x3B,0x15,0x1C,0xCE,0xD4,0xB3,0xD0,0xD1,0xAF,0xBB,0xCF,0x0D,0x49,0xD3,0xF2,0x8D,0xF6,0x14,0x3E,0x18,0x18,0xA5,0x19,0xCB,0xD3,0x67,0xBC,0x1B,0x12,0x68 };
unsigned char signalPublicEphemeralKey[32] = { 0x1B,0x09,0x0D,0x94,0xED,0x78,0x88,0x8C,0xA4,0x9B,0xD2,0x76,0x63,0x45,0x59,0x7B,0x3B,0xEA,0x8F,0x89,0x3E,0x2C,0xBB,0xFA,0xB0,0xB4,0x67,0x58,0x62,0x58,0x89,0x37 };


//////////////////////////////////////////////////////////////////////
// Shared keys (after X3DH)
//////////////////////////////////////////////////////////////////////

unsigned char sharedRootKey[32] = { 0x5f, 0x7f, 0xa2, 0x5f, 0x38, 0x79, 0x1f, 0xd4, 0xe9, 0x31, 0x32, 0x0e, 0xd1, 0xd1, 0xbf, 0x4c, 0xe8, 0xe8, 0x79, 0x18, 0x2c, 0xf6, 0x1a, 0x5e, 0x3f, 0x10, 0x41, 0x18, 0x0d, 0xf2, 0x56, 0x41 };
unsigned char sharedChainKey[32] = { 0x25, 0x5b, 0xac, 0x62, 0x6a, 0x8f, 0xa7, 0xe6, 0x28, 0x78, 0x1c, 0x1f, 0x06, 0x06, 0x40, 0xa3, 0x21, 0xd8, 0x01, 0xee, 0xe4, 0xd1, 0xfc, 0xcc, 0xc0, 0xc0, 0x42, 0x9b, 0x2c, 0x49, 0xc7, 0xfa };
