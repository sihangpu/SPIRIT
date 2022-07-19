#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "../spirit.h"
#include "../randombytes.h"

#define MLEN 59

#if (FALCON_LOGN > 5)
#define NTESTS 100
#else
#define NTESTS 1000
#endif

int main(void)
{
  uint8_t msg[MLEN];
  MPK mpk;
  MSK msk;
  MTK mtk;
  OPK_TKI opk;

#if (SS_WITH_KEY_EXPOSURE == 0)
  OSK_INSEC osk;
#else
  OSK_SEC osk_w;
  Tag tag;
  osk_w.tag = &tag;
#endif

#if (FALCON_LOGN == 0)
  uint8_t sig[CRYPTO_BYTES];
#elif (FALCON_LOGN > 0)
  uint8_t sig[FALCON_SIG_COMPRESSED_MAXSIZE(FALCON_LOGN)];
  int falcon_sig_size = 0;
#endif

  size_t i, siglen;
  int res;
  float t_gen = 0, t_opk = 0, t_osk = 0, t_track = 0, t_sign = 0, t_vrf = 0;

  for (i = 0; i < NTESTS; ++i)
  {
    randombytes(msg, MLEN);

    int start = clock();
    res = MKGen(&mpk, &msk, &mtk);

    int mid0 = clock();
    res |= OPKGen(&mpk, &opk);

    int mid1 = clock();
    res |= Track(&mpk, &mtk, &opk);
    if (res)
    {
      fprintf(stderr, "Tracking failed\n");
      return 1;
    }

    int mid2 = clock();
#if (SS_WITH_KEY_EXPOSURE == 0)
    res |= OSKGen(&mpk, &opk, &msk, &osk);
#elif (SS_WITH_KEY_EXPOSURE == 1)
    res |= OSKGen_w(&mpk, &opk, &msk, &osk_w);
#endif

    int mid3 = clock();
#if (SS_WITH_KEY_EXPOSURE == 0)
    res |= Sign(sig, &siglen, msg, MLEN, &osk);
#elif (SS_WITH_KEY_EXPOSURE == 1)
#if (FALCON_LOGN > 0)
    siglen = FALCON_SIG_COMPRESSED_MAXSIZE(FALCON_LOGN);
#endif
    res |= Sign_w(sig, &tag, &siglen, msg, MLEN, &osk_w);

#endif

    int mid4 = clock();
#if (SS_WITH_KEY_EXPOSURE == 0)
    res |= Verify(sig, siglen, msg, MLEN, &opk);
#elif (SS_WITH_KEY_EXPOSURE == 1)
    res |= Verify_w(&opk, &tag, msg, MLEN, sig, siglen);
#endif
    int end = clock();

    if (res)
    {
      fprintf(stderr, "Verification failed\n");
      return 1;
    }
    t_gen += mid0 - start;
    t_opk += mid1 - mid0;
    t_track += mid2 - mid1;
    t_osk += mid3 - mid2;
    t_sign += mid4 - mid3;
    t_vrf += end - mid4;
#if (FALCON_LOGN > 0)
    falcon_sig_size += siglen;
#endif
  }

#if (SS_WITH_KEY_EXPOSURE == 0)
  printf("\nSPIRIT w/o KEY_EXPOSURE_SECURITY\n");
  printf("\nSEC_LEVEL: %d USING %s and %s \n", KYBER_K << 6, CRYPTO_SIG_ALGNAME, CRYPTO_KEM_ALGNAME);
  printf("OPK_BYTES = %d Bytes\n", KYBER_CIPHERTEXTBYTES + CRYPTO_PUBLICKEYBYTES);
  printf("SIGNATURE_BYTES = %d Bytes\n", CRYPTO_BYTES);
#elif ((SS_WITH_KEY_EXPOSURE == 1) && (FALCON_LOGN == 0))
  printf("\nSPIRIT w/ KEY_EXPOSURE_SECURITY\n");
  printf("\nSEC_LEVEL: %d USING %s and %s \n", KYBER_K << 6, CRYPTO_SIG_ALGNAME, CRYPTO_KEM_ALGNAME);
  printf("OPK_BYTES = %d Bytes\n", KYBER_CIPHERTEXTBYTES + CRYPTO_PUBLICKEYBYTES);
  printf("SIGNATURE_BYTES = %d Bytes\n", (CRYPTO_BYTES * 2 + CRYPTO_PUBLICKEYBYTES));
#elif ((SS_WITH_KEY_EXPOSURE == 1) && (FALCON_LOGN > 0))
  printf("\nSPIRIT w/ KEY_EXPOSURE_SECURITY\n");
  printf("\nSEC_LEVEL: %d USING %s + Falcon%d and %s \n", KYBER_K << 6, CRYPTO_SIG_ALGNAME, 1 << FALCON_LOGN, CRYPTO_KEM_ALGNAME);
  printf("OPK_BYTES = %d Bytes\n", KYBER_CIPHERTEXTBYTES + CRYPTO_PUBLICKEYBYTES);
  printf("SIGNATURE_BYTES = %d Bytes\n", (CRYPTO_BYTES + FALCON_PUBKEY_SIZE(FALCON_LOGN) + (int)(falcon_sig_size / NTESTS)));
#endif

  printf("\nMKGen_TIME = %f ms \n", 1000 * (t_gen / NTESTS) / CLOCKS_PER_SEC);
  printf("OPKGen_TIME = %f ms \n", 1000 * (t_opk / NTESTS) / CLOCKS_PER_SEC);
  printf("Track_TIME = %f ms \n", 1000 * (t_track / NTESTS) / CLOCKS_PER_SEC);
  printf("OSKGen_TIME = %f ms \n", 1000 * (t_osk / NTESTS) / CLOCKS_PER_SEC);
  printf("Sign_TIME = %f ms \n", 1000 * (t_sign / NTESTS) / CLOCKS_PER_SEC);
  printf("Vf_TIME = %f ms \n", 1000 * (t_vrf / NTESTS) / CLOCKS_PER_SEC);
  return 0;
}
