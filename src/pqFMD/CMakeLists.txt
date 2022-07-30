
 # For post-quantum FMD tracking

 cmake_minimum_required(VERSION 3.13)

 if(MSVC)
  add_compile_options(/nologo /O2 /W4 /wd4146 /wd4244)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
  add_compile_options(-Werror)
  add_compile_options(-Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith)
  add_compile_options(-O3 -fomit-frame-pointer)

  # add_compile_options(-I/opt/homebrew/Cellar/gsl/2.7.1/include)
  # add_link_options(-L/opt/homebrew/Cellar/gsl/2.7.1/lib)
 
endif()


set(PQFMD_SRCS cbd.c fips202.c multi.c pack_unpack.c poly.c indcpa.c  randombytes.c)



add_library(pq_fmd_20_10 ${PQFMD_SRCS})
target_compile_definitions(pq_fmd_20_10 PUBLIC FMD_N=20 FMD_T=10)
target_link_libraries(pq_fmd_20_10)

add_library(pq_fmd_20_12 ${PQFMD_SRCS})
target_compile_definitions(pq_fmd_20_12 PUBLIC FMD_N=20 FMD_T=12)
target_link_libraries(pq_fmd_20_12)


add_library(pq_fmd_30_15 ${PQFMD_SRCS})
target_compile_definitions(pq_fmd_30_15 PUBLIC FMD_N=30 FMD_T=15)
target_link_libraries(pq_fmd_30_15)


add_executable(test_pq_fmd_20_10 test/test_pq_fmd.c)
target_link_libraries(test_pq_fmd_20_10 pq_fmd_20_10)

add_executable(test_pq_fmd_20_12 test/test_pq_fmd.c)
target_link_libraries(test_pq_fmd_20_12 pq_fmd_20_12)

add_executable(test_pq_fmd_30_15 test/test_pq_fmd.c)
target_link_libraries(test_pq_fmd_30_15 pq_fmd_30_15)
