#include "keys.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "common.h"
#include "curve.h"
#include "keygen.h"
#include "signal_protocol.h"
#include "test_common.h"
#include "ge.h"
#include "xeddsa.h"
#include "crypto_additions.h"
#include "fe.h"
#include "keygen.h"

// Internal forward declaration, used for testing the derived keys
int ratcheting_session_calculate_derived_keys(ratchet_root_key **root_key, ratchet_chain_key **chain_key, uint8_t *secret, size_t secret_len, signal_context *global_context);

// Extracted from libSignal xed25519_sign
void convert_curve_to_ed_pk(unsigned char* A, unsigned char* k) {
  ge_p3 ed_pubkey_point;
  ge_scalarmult_base(&ed_pubkey_point, k);
  ge_p3_tobytes(A, &ed_pubkey_point);
  A[31] &= 0x7F;
}

void load_public_key(ec_public_key **public_key, const unsigned char* key) {
  unsigned char tmp[33];
  tmp[0] = 0x5;
  memcpy(&tmp[1], key, 32);
  int result = curve_decode_point(public_key, tmp, 33, NULL);
  assert(result == 0);
}

void load_private_key(ec_private_key **private_key, const unsigned char* key) {
  int result = curve_decode_private_point(private_key, key, 32, NULL);
  assert(result == 0);
}


int main(int argc, char* argv[]) {
  int r;
  signal_context* context;
  r = signal_context_create(&context, 0);
  assert(r == 0);
  signal_crypto_provider provider = {
    .random_func = test_random_generator,
    .hmac_sha256_init_func = test_hmac_sha256_init,
    .hmac_sha256_update_func = test_hmac_sha256_update,
    .hmac_sha256_final_func = test_hmac_sha256_final,
    .hmac_sha256_cleanup_func = test_hmac_sha256_cleanup,
    .user_data = 0
  };
  signal_context_set_crypto_provider(context, &provider);


  //////////////////////////////////////////////////////////////////////
  // Generate Ed25519 identity key.
  //
  // This can happen outside of libsignal when publishing the device
  // bundle.
  //////////////////////////////////////////////////////////////////////
  {
    unsigned char signalPublicIdentityKey_[32];
    convert_curve_to_ed_pk(signalPublicIdentityKey_, signalPrivateCurveIdentityKey);
    assert(memcmp(signalPublicIdentityKey, signalPublicIdentityKey_, 32) == 0);
  }


  //////////////////////////////////////////////////////////////////////
  // Sign our prekey (using XEdDSA)
  //
  // This already happens in libsignal, so this is just here for
  // testing.
  //////////////////////////////////////////////////////////////////////
  { 
    unsigned char signalPublicSignedPreKeySignature_[64];
    unsigned char random[64];
    memset(random, 0, 64);
    r = xed25519_sign(signalPublicSignedPreKeySignature_, signalPrivateCurveIdentityKey, signalPublicSignedPreKey, 32, random);
    assert(r == 0);
    assert(memcmp(signalPublicSignedPreKeySignature_, signalPublicSignedPreKeySignature, 64) == 0);

    r = xed25519_verify(signalPublicSignedPreKeySignature_, signalPublicCurveIdentityKey, signalPublicSignedPreKey, 32);
    assert(r == 0);
  }


  //////////////////////////////////////////////////////////////////////
  // Signature verification
  //
  // session_builder.c:session_builder_process_pre_key_bundle() needs to be 
  // adapted to use standard EdDSA to verify signatures instead of 
  // XEdDSA (curve_verify_signature()).
  //////////////////////////////////////////////////////////////////////
  {
    unsigned char sm[64 + 32];
    unsigned char m[64 + 32];
    memcpy(sm, sodiumPublicSignedPreKeySignature, 64);
    memcpy(sm + 64, sodiumPublicSignedPreKey, 32);
    r = crypto_sign_open_modified(m, sm, sizeof(sm), sodiumPublicIdentityKey);
    assert(r == 0);
  }


  //////////////////////////////////////////////////////////////////////
  // Olm 3DH Key exchange.
  //
  // ratchet.c:ratcheting_session_alice_initialize() and 
  // ratchet.c:ratcheting_session_bob_initialize() 
  // need to be changed
  //
  // Below is a stripped down version of ratcheting_session_bob_initialize()
  // for testing the exchange.
  //////////////////////////////////////////////////////////////////////

  ec_public_key* sodiumPublicSignedPreKeyPtr = 0;
  load_public_key(&sodiumPublicSignedPreKeyPtr, sodiumPublicSignedPreKey);

  ec_public_key* sodiumPublicEphemeralKeyPtr = 0;
  load_public_key(&sodiumPublicEphemeralKeyPtr, sodiumPublicEphemeralKey);

  ec_private_key* signalPrivateSignedPreKeyPtr = 0;
  load_private_key(&signalPrivateSignedPreKeyPtr, signalPrivateSignedPreKey);

  ec_private_key* signalPrivateOTPreKeyPtr = 0;
  load_private_key(&signalPrivateOTPreKeyPtr, signalPrivateOTPreKey);

  unsigned char km[32*3];

  unsigned char* agreement;
  r = curve_calculate_agreement(&agreement, sodiumPublicSignedPreKeyPtr, signalPrivateOTPreKeyPtr);
  assert(r >= 0);
  memcpy(km, agreement, 32);

  r = curve_calculate_agreement(&agreement, sodiumPublicEphemeralKeyPtr, signalPrivateSignedPreKeyPtr);
  assert(r == 32);
  memcpy(km + 32, agreement, 32);

  r = curve_calculate_agreement(&agreement, sodiumPublicEphemeralKeyPtr, signalPrivateOTPreKeyPtr);
  assert(r == 32);
  memcpy(km + 64, agreement, 32);

  ratchet_root_key* root_key;
  ratchet_chain_key* chain_key;
  r = ratcheting_session_calculate_derived_keys(&root_key, &chain_key, km, 32*3, context);
  assert(r == 0);

  signal_buffer* bytes;
  r = ratchet_root_key_get_key(root_key, &bytes);
  assert(r == 0);
  assert(memcmp(signal_buffer_data(bytes), sharedRootKey, 32) == 0);

  r = ratchet_chain_key_get_key(chain_key, &bytes);
  assert(r == 0);
  assert(memcmp(signal_buffer_data(bytes), sharedChainKey, 32) == 0);
}

