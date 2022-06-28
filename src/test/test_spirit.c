#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../randombytes.h"
#include "../sign.h"
#include <time.h>

#include "../kyber/ref/api.h"
#include "../packing.h"
#include "../symmetric.h"

#define MLEN 59
#define NTESTS 1000

static uint8_t MKGen(polyveck *t,
                     uint8_t *pk,
                     uint8_t *sk,
                     uint8_t *ek,
                     uint8_t *dk)
{
  uint8_t rckem = pqcrystals_kyber512_ref_keypair(ek, dk);
  if (rckem)
    return 1;

  uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
  uint8_t tr[SEEDBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t0, t1;

  /* Get randomness for rho, rhoprime and key */
  randombytes(seedbuf, SEEDBYTES);
  shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES);
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES;
  key = rhoprime + CRHBYTES;

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  polyveck_add(t, &t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(t);
  polyveck_power2round(&t1, &t0, t);
  pack_pk(pk, rho, &t1);
  /* Compute H(rho, t1) and write secret key */
  shake256(tr, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  return 0;
}

static uint8_t OPKGen(const polyveck *t,
                      const uint8_t *ek,
                      const uint8_t *pk,
                      uint8_t *opk,
                      uint8_t *ct)
{
  uint8_t seedbuf[CRHBYTES];
  const uint8_t *rhoprime;
  uint8_t rho[SEEDBYTES];
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  uint8_t rckem = pqcrystals_kyber512_ref_enc(ct, seedbuf, ek);
  if (rckem)
    return 1;

  shake256(seedbuf, CRHBYTES, seedbuf, SEEDBYTES);
  rhoprime = seedbuf;

  unpack_pk(rho, &t1, pk);
  polyvec_matrix_expand(mat, rho);

  /* Sample s1' and s2' */
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);

  /*  As1' + s2' */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);
  polyveck_add(&t1, &t1, &s2);
  polyveck_caddq(&t1);
  /*  t' = t + As1'+s2' */
  polyveck_add(&t1, &t1, t);
  polyveck_reduce(&t1);
  polyveck_caddq(&t1);
  /* Extract t1' and write opk */
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(opk, rho, &t1);
  return 0;
}

static uint8_t Track(const polyveck *t,
                     const uint8_t *dk,
                     const uint8_t *ct,
                     const uint8_t *pk,
                     const uint8_t *opk)
{
  uint8_t seedbuf[CRHBYTES];
  const uint8_t *rhoprime;
  uint8_t rho[SEEDBYTES];

  uint8_t t1packed[CRYPTO_PUBLICKEYBYTES];
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  // uint8_t key_d[pqcrystals_kyber512_BYTES];
  uint8_t rckem = pqcrystals_kyber512_ref_dec(seedbuf, ct, dk);
  if (rckem)
    return 1;
  shake256(seedbuf, CRHBYTES, seedbuf, SEEDBYTES);
  rhoprime = seedbuf;

  // track
  unpack_pk(rho, &t1, pk);
  polyvec_matrix_expand(mat, rho);
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);
  polyveck_add(&t1, &t1, &s2);
  polyveck_caddq(&t1);
  polyveck_add(&t1, &t1, t);
  polyveck_reduce(&t1);
  polyveck_caddq(&t1);
  /* Extract t1 and write public key */
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(t1packed, rho, &t1);
  for (int j = 0; j < CRYPTO_PUBLICKEYBYTES; ++j)
  {
    if (opk[j] != t1packed[j])
    {
      printf("Track failed\n");
      return -1;
    }
  }
  return 0;
}

static uint8_t OSKGen(const polyveck *t,
                      const uint8_t *pk,
                      const uint8_t *opk,
                      const uint8_t *sk,
                      const uint8_t *dk,
                      const uint8_t *ct,
                      uint8_t *osk)
{
  uint8_t seedbuf[CRHBYTES];
  const uint8_t *rhoprime;
  uint8_t rho[SEEDBYTES], tr[SEEDBYTES], key[SEEDBYTES];
  polyvecl mat[K];
  polyvecl s1, s1ori, s1hat;
  polyveck s2, s2ori, t1, t0, t0tem;

  uint8_t rckem = pqcrystals_kyber512_ref_dec(seedbuf, ct, dk);
  if (rckem)
    return 1;
  shake256(seedbuf, CRHBYTES, seedbuf, SEEDBYTES);
  rhoprime = seedbuf;

  // track
  unpack_pk(rho, &t1, pk);
  polyvec_matrix_expand(mat, rho);
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);
  polyveck_add(&t1, &t1, &s2);
  polyveck_caddq(&t1);
  polyveck_add(&t1, &t1, t);
  polyveck_reduce(&t1);
  polyveck_caddq(&t1);

  /* Extract t1 and write public key */
  polyveck_power2round(&t1, &t0, &t1);

  unpack_sk(rho, tr, key, &t0tem, &s1ori, &s2ori, sk);
  polyvecl_add(&s1, &s1, &s1ori);
  polyveck_add(&s2, &s2, &s2ori);

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, SEEDBYTES, opk, CRYPTO_PUBLICKEYBYTES);
  pack2_sk(osk, rho, tr, key, &t0, &s1, &s2);
  return 0;
}


static int Sign(uint8_t *sig,
                size_t *siglen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *osk)
{
  return crypto_sign(sig, siglen, m, mlen, osk);
}

static int Verify(uint8_t *m,
                  size_t *mlen,
                  const uint8_t *sm,
                  size_t smlen,
                  const uint8_t *opk)
{
  return crypto_sign_open(m, mlen, sm, smlen, opk);
}

static uint8_t OSKGen_w(const polyveck *t,
                      const uint8_t *pk,
                      const uint8_t *opk,
                      const uint8_t *sk,
                      const uint8_t *dk,
                      const uint8_t *ct,
                      uint8_t *sig,
                      size_t *siglen,
                      uint8_t *osk,
                      uint8_t *ovk){
    
    uint8_t epk[CRYPTO2_SECRETKEYBYTES];
    int res = OSKGen(t, pk, opk, sk, dk, ct, epk);
    crypto_sign_keypair(ovk, osk);
    res |= Sign(sig, siglen, ovk, CRYPTO_PUBLICKEYBYTES, epk);
    if (res) return -1;
    return 0;
}

static uint8_t Sign_w(uint8_t *sig,
                size_t *siglen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *osk){
    
    int res = crypto_sign(sig, siglen, m, mlen, osk);
    if (res) return -1;
    return 0;
} 

static uint8_t Verify_w(uint8_t *m,
                  size_t *mlen,
                  const uint8_t *sm,
                  size_t smlen,
                  const uint8_t *opk,
                  uint8_t *m2,
                  size_t *mlen2,
                  const uint8_t *sm2,
                  size_t smlen2,
                  const uint8_t *vk){
    
    int ret = Verify(m, mlen, sm, smlen, opk);
    ret |= Verify(m2, mlen2, sm2, smlen2, vk);
    if (ret) return -1;
    return 0;
} 
int main(void)
{

  uint8_t MSG[MLEN + CRYPTO_BYTES];
  uint8_t MSG2[MLEN + CRYPTO_BYTES];
  uint8_t SIG[MLEN + CRYPTO_BYTES];

  polyveck MPK_t;
  uint8_t MPK_pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t MSK_sk[CRYPTO_SECRETKEYBYTES];
  uint8_t OPK_opk[CRYPTO_PUBLICKEYBYTES];

  uint8_t OSK_vk[CRYPTO_PUBLICKEYBYTES+ CRYPTO_BYTES];
  uint8_t OSK_vk2[CRYPTO_PUBLICKEYBYTES+ CRYPTO_BYTES];
  uint8_t OSK_sk[CRYPTO_SECRETKEYBYTES];
  uint8_t OSK_sig[CRYPTO_PUBLICKEYBYTES + CRYPTO_BYTES];

  uint8_t MPK_ek[pqcrystals_kyber512_PUBLICKEYBYTES];
  uint8_t MSK_dk[pqcrystals_kyber512_SECRETKEYBYTES];
  uint8_t TKI_ct[pqcrystals_kyber512_CIPHERTEXTBYTES];

  size_t i; //, j;
  int ret, res;
  size_t mlen, smlen, mlen2, smlen2;
  float t_gen = 0, t_opk = 0, t_osk = 0, t_track = 0, t_sign = 0, t_vrf = 0;

  for (i = 0; i < NTESTS; ++i)
  {
    randombytes(MSG, MLEN);
    int start = clock();
    res = MKGen(&MPK_t, MPK_pk, MSK_sk, MPK_ek, MSK_dk);

    int mid0 = clock();
    res = OPKGen(&MPK_t, MPK_ek, MPK_pk, OPK_opk, TKI_ct);

    int mid1 = clock();
    res = Track(&MPK_t, MSK_dk, TKI_ct, MPK_pk, OPK_opk);
    if (res)
      return -1;

    int mid2 = clock();
    res = OSKGen_w(&MPK_t, MPK_pk, OPK_opk, MSK_sk, MSK_dk, TKI_ct, OSK_sig, &smlen, OSK_sk, OSK_vk);

    int mid3 = clock();
    res = Sign_w(SIG, &smlen2, MSG, MLEN, OSK_sk);

    int mid4 = clock();
    ret = Verify_w(OSK_vk2, &mlen, OSK_sig, smlen, OPK_opk, MSG2, &mlen2, SIG, smlen2, OSK_vk);

    int end = clock();

    if (ret)
    {
      fprintf(stderr, "Verification failed\n");
      return -1;
    }

    t_gen += mid0 - start;
    t_opk += mid1 - mid0;
    t_track += mid2 - mid1;
    t_osk += mid3 - mid2;
    t_sign += mid4 - mid3;
    t_vrf += end - mid4;
  }

  printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO2_SECRETKEYBYTES);
  printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);
  printf("MKGen_TIME = %f ms \n", 1000 * (t_gen / NTESTS) / CLOCKS_PER_SEC);
  printf("OPKGen_TIME = %f ms \n", 1000 * (t_opk / NTESTS) / CLOCKS_PER_SEC);
  printf("Track_TIME = %f ms \n", 1000 * (t_track / NTESTS) / CLOCKS_PER_SEC);
  printf("OSKGen_TIME = %f ms \n", 1000 * (t_osk / NTESTS) / CLOCKS_PER_SEC);
  printf("Sign_TIME = %f ms \n", 1000 * (t_sign / NTESTS) / CLOCKS_PER_SEC);
  printf("Vf_TIME = %f ms \n", 1000 * (t_vrf / NTESTS) / CLOCKS_PER_SEC);
  return 0;
}
