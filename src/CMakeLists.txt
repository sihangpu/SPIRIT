set(DILITHIUM_SRCS sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c)
set(DILITHIUM_FIPS202_SRCS ${DILITHIUM_SRCS} symmetric-shake.c)

set(FIPS202_SRCS fips202.c)
set(AES256CTR_SRCS aes256ctr.c)

set(KYBER_SRCS kyber/ref/kex.c kyber/ref/kem.c kyber/ref/indcpa.c kyber/ref/polyvec.c kyber/ref/poly.c kyber/ref/ntt.c kyber/ref/cbd.c kyber/ref/reduce.c kyber/ref/verify.c)
set(KYBER_FIPS202_SRCS ${KYBER_SRCS} kyber/ref/symmetric-shake.c)
set(SHA2_SRCS kyber/ref/sha256.c kyber/ref/sha512.c)
set(FIPS202_KYBER_SRCS kyber/ref/fips202.c)

set(TEST_SPIRIT_SRCS test/test_spirit.c randombytes.c)

if(MSVC)
  add_compile_options(/nologo /O2 /W4 /wd4146 /wd4244)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
  add_compile_options(-Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith)
  add_compile_options(-O3 -fomit-frame-pointer)
endif()

add_library(fips202_ref ${FIPS202_SRCS})
add_library(aes256ctr_ref ${AES256CTR_SRCS})
add_library(sha2_ref ${SHA2_SRCS})
add_library(fips202_kyber_ref ${FIPS202_KYBER_SRCS})

# Kyber512
add_library(kyber512_ref ${KYBER_FIPS202_SRCS})
target_compile_definitions(kyber512_ref PUBLIC KYBER_K=2)
target_link_libraries(kyber512_ref INTERFACE fips202_kyber_ref)

# Dilithium 2
add_library(dilithium2_ref ${DILITHIUM_FIPS202_SRCS})
target_compile_definitions(dilithium2_ref PUBLIC DILITHIUM_MODE=2)
target_link_libraries(dilithium2_ref INTERFACE fips202_ref)

add_executable(test_spirit_ref ${TEST_SPIRIT_SRCS})
target_link_libraries(test_spirit_ref dilithium2_ref kyber512_ref)


