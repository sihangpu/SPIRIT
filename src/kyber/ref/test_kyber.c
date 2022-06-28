#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "kem.h"
#include "randombytes.h"
#include <time.h>
#define NTESTS 1000

float t_gen=0,t_enc=0,t_dec=0;
int start, mid1, mid2, end;
static int test_keys()
{
  uint8_t pk[KYBER_PUBLICKEYBYTES];
  uint8_t sk[KYBER_SECRETKEYBYTES];
  uint8_t ct[KYBER_CIPHERTEXTBYTES];
  uint8_t key_a[KYBER_SSBYTES];
  uint8_t key_b[KYBER_SSBYTES];
   start = clock();
  //Alice generates a public key
  crypto_kem_keypair(pk, sk);
   mid1 = clock();
  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);
   mid2 = clock();
  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);
   end = clock();
  if(memcmp(key_a, key_b, KYBER_SSBYTES)) {
    printf("ERROR keys\n");
    return 1;
  }

  return 0;
}

static int test_invalid_sk_a()
{
  uint8_t pk[KYBER_PUBLICKEYBYTES];
  uint8_t sk[KYBER_SECRETKEYBYTES];
  uint8_t ct[KYBER_CIPHERTEXTBYTES];
  uint8_t key_a[KYBER_SSBYTES];
  uint8_t key_b[KYBER_SSBYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Replace secret key with random values
  randombytes(sk, KYBER_SECRETKEYBYTES);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, KYBER_SSBYTES)) {
    printf("ERROR invalid sk\n");
    return 1;
  }

  return 0;
}

static int test_invalid_ciphertext()
{
  uint8_t pk[KYBER_PUBLICKEYBYTES];
  uint8_t sk[KYBER_SECRETKEYBYTES];
  uint8_t ct[KYBER_CIPHERTEXTBYTES];
  uint8_t key_a[KYBER_SSBYTES];
  uint8_t key_b[KYBER_SSBYTES];
  uint8_t b;
  size_t pos;

  do {
    randombytes(&b, sizeof(uint8_t));
  } while(!b);
  randombytes((uint8_t *)&pos, sizeof(size_t));

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Change some byte in the ciphertext (i.e., encapsulated key)
  ct[pos % KYBER_CIPHERTEXTBYTES] ^= b;

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, KYBER_SSBYTES)) {
    printf("ERROR invalid ciphertext\n");
    return 1;
  }

  return 0;
}

int main(void)
{
  unsigned int i;
  int r;

  for(i=0;i<NTESTS;i++) {
    r  = test_keys();
    r |= test_invalid_sk_a();
    r |= test_invalid_ciphertext();
    t_gen += mid1-start;
    t_enc += mid2-mid1;
    t_dec += end-mid2;
    if(r)
      return 1;
  }

  printf("KYBER_SECRETKEYBYTES:  %d\n",KYBER_SECRETKEYBYTES);
  printf("KYBER_PUBLICKEYBYTES:  %d\n",KYBER_PUBLICKEYBYTES);
  printf("KYBER_CIPHERTEXTBYTES: %d\n",KYBER_CIPHERTEXTBYTES);
   printf("KEYGEN_TIME = %f ms \n", 1000*(t_gen/NTESTS)/CLOCKS_PER_SEC);
  printf("Enc_TIME = %f ms \n", 1000*(t_enc/NTESTS)/CLOCKS_PER_SEC);
  printf("Dec_TIME = %f ms \n", 1000*(t_dec/NTESTS)/CLOCKS_PER_SEC);

  return 0;
}
