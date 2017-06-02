#include "keys.h"
#include "sodium.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "common.h"

const char* info = "WhisperText";

// A hard-coded HKDF. Use a real one instead.
void kdf(unsigned char* okm, unsigned char* km) {
  unsigned char salt[32], prk[32], t[32];
  int err;

  memset(salt, 0, 32);
  err = crypto_auth_hmacsha256(prk, km, 32*3, salt);
  assert(err == 0);

  unsigned char i1[11+1], t1[32];
  memcpy(i1, info, 11);
  i1[11] = 0x01;
  err = crypto_auth_hmacsha256(t1, i1, 11+1, prk);
  assert(err == 0);

  unsigned char i2[32 + 11 + 1], t2[32];
  memcpy(i2, t1, 32);
  memcpy(i2 + 32, info, 11);
  i2[32 + 11] = 0x2;
  err = crypto_auth_hmacsha256(t2, i2, 32 + 11+1, prk);
  assert(err == 0);

  memmove(okm, t1, 32);
  memmove(okm + 32, t2, 32);
}

int main(int argc, char* argv[]) {
  int err;

  //////////////////////////////////////////////////////////////////////
  // Sign prekey
  //////////////////////////////////////////////////////////////////////
  {
    unsigned char sodiumPublicSignedPreKeySignature_[64];
    err = crypto_sign_detached(
        sodiumPublicSignedPreKeySignature_, NULL,
        sodiumPublicSignedPreKey, sizeof(sodiumPublicSignedPreKey),
        sodiumPrivateIdentityKey);
    assert(err == 0);
    assert(memcmp(sodiumPublicSignedPreKeySignature_, sodiumPublicSignedPreKeySignature, 64) == 0);
  }


  //////////////////////////////////////////////////////////////////////
  // Signature Verification
  //////////////////////////////////////////////////////////////////////
  err = crypto_sign_verify_detached(signalPublicSignedPreKeySignature, signalPublicSignedPreKey, 32, signalPublicIdentityKey);
  if (err != 0) { printf("Error: Verifying OTK signature\n"); return -1; }


  //////////////////////////////////////////////////////////////////////
  //  DH Key exchange
  //////////////////////////////////////////////////////////////////////

  unsigned char km[32*3];
  err = crypto_scalarmult(km, sodiumPrivateSignedPreKey, signalPublicOTPreKey);
  assert(err == 0);
  err = crypto_scalarmult(km + 32, sodiumPrivateEphemeralKey, signalPublicSignedPreKey);
  assert(err == 0);
  err = crypto_scalarmult(km + 64, sodiumPrivateEphemeralKey, signalPublicOTPreKey);
  assert(err == 0);

  unsigned char sharedKeys[64];
  kdf(sharedKeys, km);

  assert(memcmp(sharedKeys, sharedRootKey, 32) == 0);
  assert(memcmp(sharedKeys + 32, sharedChainKey, 32) == 0);
}
