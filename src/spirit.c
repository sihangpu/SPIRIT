#include <stdio.h>
#include "spirit.h"

int MKGen(MPK *mpk, MSK *msk, MTK *mtk)
{
  int rckem = crypto_kem_keypair(mpk->_ek_kem, msk->_dk_kem);
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
  polyveck_add(&(mpk->t), &t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&(mpk->t));
  polyveck_power2round(&t1, &t0, &(mpk->t));
  pack_pk(mpk->_pk_ds, rho, &t1);
  /* Compute H(rho, t1) and write secret key */
  shake256(tr, SEEDBYTES, mpk->_pk_ds, CRYPTO_PUBLICKEYBYTES);
  pack_sk(msk->_sk_ds, rho, tr, key, &t0, &s1, &s2);

  // store mtk seperately
  for (int i = 0; i < KYBER_SECRETKEYBYTES; ++i)
    mtk->_dk_kem[i] = msk->_dk_kem[i];
  return 0;
}

int OPKGen(const MPK *mpk, OPK_TKI *opk)
{
  uint8_t seedbuf[CRHBYTES];
  const uint8_t *rhoprime;
  uint8_t rho[SEEDBYTES];
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  int rckem = crypto_kem_enc(opk->_ct_kem, seedbuf, mpk->_ek_kem);

  if (rckem)
    return 2;

  shake256(seedbuf, CRHBYTES, seedbuf, SEEDBYTES);
  rhoprime = seedbuf;

  unpack_pk(rho, &t1, mpk->_pk_ds);
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
  polyveck_add(&t1, &t1, &(mpk->t));
  polyveck_reduce(&t1);
  polyveck_caddq(&t1);
  /* Extract t1' and write opk */
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(opk->_opk_ds, rho, &t1);
  return 0;
}

int Track(const MPK *mpk, const MTK *mtk, const OPK_TKI *opk)
{
  uint8_t seedbuf[CRHBYTES];
  const uint8_t *rhoprime;
  uint8_t rho[SEEDBYTES];

  uint8_t t1packed[CRYPTO_PUBLICKEYBYTES];
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  int rckem = crypto_kem_dec(seedbuf, opk->_ct_kem, mtk->_dk_kem);
  if (rckem)
    return 3;

  shake256(seedbuf, CRHBYTES, seedbuf, SEEDBYTES);
  rhoprime = seedbuf;

  // track
  unpack_pk(rho, &t1, mpk->_pk_ds);
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
  polyveck_add(&t1, &t1, &(mpk->t));
  polyveck_reduce(&t1);
  polyveck_caddq(&t1);
  /* Extract t1 and write public key */
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(t1packed, rho, &t1);
  for (int j = 0; j < CRYPTO_PUBLICKEYBYTES; ++j)
  {
    if (opk->_opk_ds[j] != t1packed[j])
    {
      return 3;
    }
  }
  return 0;
}

int OSKGen(const MPK *mpk, const OPK_TKI *opk, const MSK *msk, OSK_INSEC *osk)
{
  uint8_t seedbuf[CRHBYTES];
  const uint8_t *rhoprime;
  uint8_t rho[SEEDBYTES], tr[SEEDBYTES], key[SEEDBYTES];
  polyvecl mat[K];
  polyvecl s1, s1ori, s1hat;
  polyveck s2, s2ori, t1, t0, t0tem;

  int rckem = crypto_kem_dec(seedbuf, opk->_ct_kem, msk->_dk_kem);
  if (rckem)
    return 4;

  shake256(seedbuf, CRHBYTES, seedbuf, SEEDBYTES);
  rhoprime = seedbuf;

  // track
  unpack_pk(rho, &t1, mpk->_pk_ds);
  polyvec_matrix_expand(mat, rho);
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);
  polyveck_add(&t1, &t1, &s2);
  polyveck_add(&t1, &t1, &(mpk->t));
  polyveck_reduce(&t1);
  polyveck_caddq(&t1);

  /* Extract t1 and write public key */
  polyveck_power2round(&t1, &t0, &t1);

  unpack_sk(rho, tr, key, &t0tem, &s1ori, &s2ori, msk->_sk_ds);
  polyvecl_add(&s1, &s1, &s1ori);
  polyveck_add(&s2, &s2, &s2ori);

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, SEEDBYTES, opk->_opk_ds, CRYPTO_PUBLICKEYBYTES);
  pack2_sk(osk->_sk_ds, rho, tr, key, &t0, &s1, &s2);
  return 0;
}

int Sign(uint8_t *sig, size_t *siglen,
         const uint8_t *m, size_t mlen,
         const OSK_INSEC *osk)
{
  return crypto_sign_signature(sig, siglen, m, mlen, osk->_sk_ds);
}

int Verify(const uint8_t *sig, size_t siglen,
           const uint8_t *m, size_t msglen,
           const OPK_TKI *opk)
{
  return crypto_sign_verify(sig, siglen, m, msglen, opk->_opk_ds);
}



#if (SS_WITH_KEY_EXPOSURE == 1)
int OSKGen_w(const MPK *mpk, const OPK_TKI *opk, const MSK *msk, OSK_SEC *osk)
{

  OSK_INSEC _temp_osk;
  int res = OSKGen(mpk, opk, msk, &_temp_osk);

#if (FALCON_LOGN == 0)

  crypto_sign_keypair(osk->tag->_vk_ds, osk->_sk_ds);
  osk->tag->_vk_ds_len = CRYPTO_PUBLICKEYBYTES;
#elif (FALCON_LOGN > 0)
  shake256_context rng;
  uint8_t tmp[FALCON_TMPSIZE_KEYGEN(FALCON_LOGN)];
  shake256_init_prng_from_system(&rng);
  res |= falcon_keygen_make(&rng, FALCON_LOGN, osk->_sk_ds, FALCON_PRIVKEY_SIZE(FALCON_LOGN),
                            osk->tag->_vk_ds, FALCON_PUBKEY_SIZE(FALCON_LOGN),
                            tmp, FALCON_TMPSIZE_KEYGEN(FALCON_LOGN));
  osk->tag->_vk_ds_len = FALCON_PUBKEY_SIZE(FALCON_LOGN);
#endif

  res |= Sign(osk->tag->_sig_ds, &(osk->tag->_siglen), osk->tag->_vk_ds, osk->tag->_vk_ds_len, &_temp_osk);
  if (res)
    return 4;
  return 0;
}



int Sign_w(uint8_t *sig, Tag *tag_sig, size_t *siglen,
           const uint8_t *m, size_t msglen,
           const OSK_SEC *osk)
{
  int res;
  size_t i;
  // store tag in signatures
  for (i = 0; i < (osk->tag->_siglen); ++i)
    tag_sig->_sig_ds[i] = osk->tag->_sig_ds[i];
  for (i = 0; i < (osk->tag->_vk_ds_len); ++i)
    tag_sig->_vk_ds[i] = osk->tag->_vk_ds[i];
  tag_sig->_siglen = osk->tag->_siglen;
  tag_sig->_vk_ds_len = osk->tag->_vk_ds_len;

#if (FALCON_LOGN == 0)
  res = crypto_sign_signature(sig, siglen, m, msglen, osk->_sk_ds);
#elif (FALCON_LOGN > 0)
  shake256_context rng;
  uint8_t tmp[FALCON_TMPSIZE_SIGNDYN(FALCON_LOGN)];
  shake256_init_prng_from_system(&rng);
  res = falcon_sign_dyn(&rng, sig, siglen, FALCON_SIG_COMPRESSED,
                        osk->_sk_ds, FALCON_PRIVKEY_SIZE(FALCON_LOGN),
                        m, msglen, tmp, FALCON_TMPSIZE_SIGNDYN(FALCON_LOGN));
#endif

  if (res)
    return 5;
  return 0;
}



int Verify_w(const OPK_TKI *opk, const Tag *tag_sig,
             const uint8_t *msg, size_t msglen,
             const uint8_t *sig, size_t siglen)
{

  int ret = Verify(tag_sig->_sig_ds, tag_sig->_siglen, tag_sig->_vk_ds, tag_sig->_vk_ds_len, opk);
#if (FALCON_LOGN == 0)
  ret |= crypto_sign_verify(sig, siglen, msg, msglen, tag_sig->_vk_ds);
#elif (FALCON_LOGN > 0)
  uint8_t tmp[FALCON_TMPSIZE_VERIFY(FALCON_LOGN)];
  ret |= falcon_verify(sig, siglen, FALCON_SIG_COMPRESSED,
                       tag_sig->_vk_ds, FALCON_PUBKEY_SIZE(FALCON_LOGN),
                       msg, msglen,
                       tmp, FALCON_TMPSIZE_VERIFY(FALCON_LOGN));
#endif
  if (ret)
    return 6;
  return 0;
}


#endif
