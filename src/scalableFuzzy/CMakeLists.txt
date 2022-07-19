
 # Created by Daniel Norte de Moraes <danielcheagle@gmail.com>
 # for Saber PQC Project.
 # License: Public Domain <Unlicense>

 # Adapted for Kyber_ind_cpa

 cmake_minimum_required(VERSION 3.10)

 set(CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "" FORCE)

 if(NOT CMAKE_BUILD_TYPE)
     set(CMAKE_BUILD_TYPE Release)
 endif()

 if(MSVC)
 else()
     set(CMAKE_C_FLAGS "-Wall -Wextra -Wmissing-prototypes -Wredundant-decls -fomit-frame-pointer")
     set(CMAKE_C_FLAGS_RELEASE "-O3")
 endif()

 
 set(libfiles
   pack_unpack.c poly.c fips202.c cbd.c indcpa.c poly_mul.c randombytes.c)

 set(libheaders
   params.h pack_unpack.h poly.h fips202.h cbd.h poly_mul.h
   indcpa.h randombytes.h)


 add_library(kyber_non_NTT_ref ${libfiles} ${libheaders})
 target_link_libraries(kyber_non_NTT_ref)

 add_executable(test_scalable_fuzzy ${libheaders} test/test_scalable_fuzzy.c)
 target_link_libraries(test_scalable_fuzzy kyber_non_NTT_ref)
