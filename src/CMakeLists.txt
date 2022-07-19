# Signatures
set(DILITHIUM_SRCS sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c)
set(DILITHIUM_FIPS202_SRCS ${DILITHIUM_SRCS} symmetric-shake.c)
set(FIPS202_SRCS fips202.c)
set(AES256CTR_SRCS aes256ctr.c)

set(FALCON_SRCS falcon/codec.c falcon/common.c falcon/falcon.c falcon/fft.c falcon/fpr.c falcon/keygen.c falcon/rng.c falcon/shake.c falcon/sign.c falcon/vrfy.c)


# KEMs
set(KYBER_SRCS kyber/ref/kex.c kyber/ref/kem.c kyber/ref/indcpa.c kyber/ref/polyvec.c kyber/ref/poly.c kyber/ref/ntt.c kyber/ref/cbd.c kyber/ref/reduce.c kyber/ref/verify.c)
set(KYBER_FIPS202_SRCS ${KYBER_SRCS} kyber/ref/symmetric-shake.c)
set(SHA2_SRCS kyber/ref/sha256.c kyber/ref/sha512.c)
set(FIPS202_KYBER_SRCS kyber/ref/fips202.c)


# SPIRIT
set(SPIRIT_SRCS spirit.c)

# Tests
set(TEST_SPIRIT_SRCS test/test_spirit.c randombytes.c)

if(MSVC)
  add_compile_options(/nologo /O2 /W4 /wd4146 /wd4244)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
  add_compile_options(-Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith)
  add_compile_options(-O3 -fomit-frame-pointer)
endif()

# Utils
add_library(fips202_ref ${FIPS202_SRCS})
add_library(aes256ctr_ref ${AES256CTR_SRCS})
add_library(sha2_ref ${SHA2_SRCS})
add_library(fips202_kyber_ref ${FIPS202_KYBER_SRCS})

# Kyber512
add_library(kyber512_ref ${KYBER_FIPS202_SRCS})
target_compile_definitions(kyber512_ref PUBLIC KYBER_K=2)
target_link_libraries(kyber512_ref INTERFACE fips202_kyber_ref)

# Kyber768
add_library(kyber768_ref ${KYBER_FIPS202_SRCS})
target_compile_definitions(kyber768_ref PUBLIC KYBER_K=3)
target_link_libraries(kyber768_ref INTERFACE fips202_kyber_ref)

# Kyber 1024
add_library(kyber1024_ref ${KYBER_FIPS202_SRCS})
target_compile_definitions(kyber1024_ref PUBLIC KYBER_K=4)
target_link_libraries(kyber1024_ref INTERFACE fips202_kyber_ref)

# Falcon
add_library(falcon ${FALCON_SRCS} )
target_compile_definitions(falcon PUBLIC )
target_link_libraries(falcon INTERFACE)

# Dilithium 2
add_library(dilithium2_ref ${DILITHIUM_FIPS202_SRCS})
target_compile_definitions(dilithium2_ref PUBLIC DILITHIUM_MODE=2)
target_link_libraries(dilithium2_ref INTERFACE fips202_ref)

# Dilithium 3
add_library(dilithium3_ref ${DILITHIUM_FIPS202_SRCS})
target_compile_definitions(dilithium3_ref PUBLIC DILITHIUM_MODE=3)
target_link_libraries(dilithium3_ref INTERFACE fips202_ref)

# Dilithium 5
add_library(dilithium5_ref ${DILITHIUM_FIPS202_SRCS})
target_compile_definitions(dilithium5_ref PUBLIC DILITHIUM_MODE=5)
target_link_libraries(dilithium5_ref INTERFACE fips202_ref)

# Spirit 2 w/o-ke
add_library(spirit_2_wo_ke ${SPIRIT_SRCS})
target_compile_definitions(spirit_2_wo_ke PUBLIC DILITHIUM_MODE=2 KYBER_K=2 SS_WITH_KEY_EXPOSURE=0)
target_link_libraries(spirit_2_wo_ke INTERFACE dilithium2_ref kyber512_ref falcon)

# Spirit 3 w/o-ke
add_library(spirit_3_wo_ke ${SPIRIT_SRCS})
target_compile_definitions(spirit_3_wo_ke PUBLIC DILITHIUM_MODE=3 KYBER_K=3 SS_WITH_KEY_EXPOSURE=0)
target_link_libraries(spirit_3_wo_ke INTERFACE dilithium3_ref kyber768_ref falcon)

# Spirit 5 w/o-ke
add_library(spirit_5_wo_ke ${SPIRIT_SRCS})
target_compile_definitions(spirit_5_wo_ke PUBLIC DILITHIUM_MODE=5 KYBER_K=4 SS_WITH_KEY_EXPOSURE=0)
target_link_libraries(spirit_5_wo_ke INTERFACE dilithium5_ref kyber1024_ref falcon)

# Spirit 2 w/-ke Dilithium+Dilithium
add_library(spirit_2_w_ke ${SPIRIT_SRCS})
target_compile_definitions(spirit_2_w_ke  PUBLIC DILITHIUM_MODE=2 KYBER_K=2 SS_WITH_KEY_EXPOSURE=1)
target_link_libraries(spirit_2_w_ke  INTERFACE dilithium2_ref kyber512_ref falcon)

# Spirit 3 w/-ke Dilithium+Dilithium
add_library(spirit_3_w_ke  ${SPIRIT_SRCS})
target_compile_definitions(spirit_3_w_ke  PUBLIC DILITHIUM_MODE=3 KYBER_K=3 SS_WITH_KEY_EXPOSURE=1)
target_link_libraries(spirit_3_w_ke  INTERFACE dilithium3_ref kyber768_ref falcon)

# Spirit 5 w/-ke Dilithium+Dilithium
add_library(spirit_5_w_ke  ${SPIRIT_SRCS})
target_compile_definitions(spirit_5_w_ke  PUBLIC DILITHIUM_MODE=5 KYBER_K=4 SS_WITH_KEY_EXPOSURE=1)
target_link_libraries(spirit_5_w_ke  INTERFACE dilithium5_ref kyber1024_ref falcon)

# Spirit 2 w/-ke Dilithium+Falcon
add_library(spirit_2_w_ke_falcon ${SPIRIT_SRCS})
target_compile_definitions(spirit_2_w_ke_falcon PUBLIC DILITHIUM_MODE=2 KYBER_K=2 SS_WITH_KEY_EXPOSURE=1 FALCON_LOGN=9)
target_link_libraries(spirit_2_w_ke_falcon INTERFACE dilithium2_ref kyber512_ref falcon)

# Spirit 3 w/-ke Dilithium+Falcon
add_library(spirit_3_w_ke_falcon ${SPIRIT_SRCS})
target_compile_definitions(spirit_3_w_ke_falcon PUBLIC DILITHIUM_MODE=3 KYBER_K=3 SS_WITH_KEY_EXPOSURE=1 FALCON_LOGN=10)
target_link_libraries(spirit_3_w_ke_falcon INTERFACE dilithium3_ref kyber768_ref falcon)

# Spirit 5 w/-ke Dilithium+Falcon
add_library(spirit_5_w_ke_falcon ${SPIRIT_SRCS})
target_compile_definitions(spirit_5_w_ke_falcon PUBLIC DILITHIUM_MODE=5 KYBER_K=4 SS_WITH_KEY_EXPOSURE=1 FALCON_LOGN=10)
target_link_libraries(spirit_5_w_ke_falcon INTERFACE dilithium5_ref kyber1024_ref falcon)

# Tests
add_executable(test_spirit_2_wo_ke ${TEST_SPIRIT_SRCS})
target_link_libraries(test_spirit_2_wo_ke spirit_2_wo_ke dilithium2_ref kyber512_ref falcon)

add_executable(test_spirit_3_wo_ke ${TEST_SPIRIT_SRCS})
target_link_libraries(test_spirit_3_wo_ke spirit_3_wo_ke dilithium3_ref kyber768_ref falcon)

add_executable(test_spirit_5_wo_ke ${TEST_SPIRIT_SRCS})
target_link_libraries(test_spirit_5_wo_ke spirit_5_wo_ke dilithium5_ref kyber1024_ref falcon)

add_executable(test_spirit_2_w_ke ${TEST_SPIRIT_SRCS})
target_link_libraries(test_spirit_2_w_ke spirit_2_w_ke dilithium2_ref kyber512_ref falcon)

add_executable(test_spirit_3_w_ke ${TEST_SPIRIT_SRCS})
target_link_libraries(test_spirit_3_w_ke spirit_3_w_ke dilithium3_ref kyber768_ref falcon)

add_executable(test_spirit_5_w_ke ${TEST_SPIRIT_SRCS})
target_link_libraries(test_spirit_5_w_ke spirit_5_w_ke dilithium5_ref kyber1024_ref falcon)

add_executable(test_spirit_2_w_ke_falcon ${TEST_SPIRIT_SRCS})
target_link_libraries(test_spirit_2_w_ke_falcon spirit_2_w_ke_falcon dilithium2_ref kyber512_ref falcon)

add_executable(test_spirit_3_w_ke_falcon ${TEST_SPIRIT_SRCS})
target_link_libraries(test_spirit_3_w_ke_falcon spirit_3_w_ke_falcon dilithium3_ref kyber768_ref falcon)

add_executable(test_spirit_5_w_ke_falcon ${TEST_SPIRIT_SRCS})
target_link_libraries(test_spirit_5_w_ke_falcon spirit_5_w_ke_falcon dilithium5_ref kyber1024_ref falcon)

