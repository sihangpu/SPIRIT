#ifndef SPIRIT_H
#define SPIRIT_H

#include <stddef.h>
#include <stdint.h>

#include "randombytes.h"
#include "sign.h"
#include "packing.h"
#include "symmetric.h"
#include "kyber/ref/kem.h"
#include "falcon/falcon.h"

#ifndef FALCON_LOGN
#define FALCON_LOGN 0
#endif

#ifndef SS_WITH_KEY_EXPOSURE
#define SS_WITH_KEY_EXPOSURE 0
#endif

typedef struct
{
    polyveck t;
    uint8_t _pk_ds[CRYPTO_PUBLICKEYBYTES];
    uint8_t _ek_kem[KYBER_PUBLICKEYBYTES];
} MPK;

typedef struct
{
    uint8_t _sk_ds[CRYPTO_SECRETKEYBYTES];
    uint8_t _dk_kem[KYBER_SECRETKEYBYTES];
} MSK;

typedef struct
{
    uint8_t _dk_kem[KYBER_SECRETKEYBYTES];
} MTK;

typedef struct
{
    uint8_t _opk_ds[CRYPTO_PUBLICKEYBYTES];
    uint8_t _ct_kem[KYBER_CIPHERTEXTBYTES];
} OPK_TKI;

typedef struct
{
    uint8_t _sk_ds[CRYPTO2_SECRETKEYBYTES];
} OSK_INSEC;

#if ((SS_WITH_KEY_EXPOSURE == 1) && (FALCON_LOGN == 0))
typedef struct
{
    uint8_t _sig_ds[CRYPTO_BYTES];
    size_t _siglen;
    size_t _vk_ds_len;
    uint8_t _vk_ds[CRYPTO_PUBLICKEYBYTES];
} Tag;
typedef struct
{
    uint8_t _sk_ds[CRYPTO2_SECRETKEYBYTES];
    Tag *tag;
} OSK_SEC;
#elif ((SS_WITH_KEY_EXPOSURE == 1) && (FALCON_LOGN > 0))
typedef struct
{
    uint8_t _sig_ds[CRYPTO_BYTES];
    size_t _siglen;
    size_t _vk_ds_len;
    uint8_t _vk_ds[FALCON_PUBKEY_SIZE(FALCON_LOGN)];
} Tag;
typedef struct
{
    uint8_t _sk_ds[FALCON_PRIVKEY_SIZE(FALCON_LOGN)];
    Tag *tag;
} OSK_SEC;
#endif

int MKGen(MPK *mpk, MSK *msk, MTK *mtk);

int OPKGen(const MPK *mpk, OPK_TKI *opk);

int Track(const MPK *mpk, const MTK *mtk, const OPK_TKI *opk);

int OSKGen(const MPK *mpk, const OPK_TKI *opk, const MSK *msk, OSK_INSEC *osk);

int Sign(uint8_t *sig, size_t *siglen,
         const uint8_t *m, size_t mlen,
         const OSK_INSEC *osk);

int Verify(const uint8_t *sig, size_t siglen,
           const uint8_t *m, size_t msglen,
           const OPK_TKI *opk);

#if (SS_WITH_KEY_EXPOSURE == 1)

int OSKGen_w(const MPK *mpk, const OPK_TKI *opk, const MSK *msk, OSK_SEC *osk);

int Sign_w(uint8_t *sig, Tag *tag_sig, size_t *siglen,
           const uint8_t *m, size_t msglen,
           const OSK_SEC *osk);

int Verify_w(const OPK_TKI *opk, const Tag *tag_sig,
             const uint8_t *msg, size_t msglen,
             const uint8_t *sig, size_t siglen);
#endif

#endif
