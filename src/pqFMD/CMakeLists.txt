
 # For post-quantum FMD tracking

 cmake_minimum_required(VERSION 3.13)

 if(MSVC)
  add_compile_options(/nologo /O2 /W4 /wd4146 /wd4244)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
  # add_compile_options(-Werror)
  add_compile_options(-Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith)
  add_compile_options(-O3 -fomit-frame-pointer)

  # add_compile_options(-I/opt/homebrew/Cellar/gsl/2.7.1/include)
  # add_link_options(-L/opt/homebrew/Cellar/gsl/2.7.1/lib)
 
endif()


set(PQFMD_SRCS cbd.c fips202.c multi.c pack_unpack.c poly.c indcpa.c  randombytes.c)



add_library(pq_fmd ${PQFMD_SRCS} )
target_link_libraries(pq_fmd)

add_executable(test_pq_fmd test/test_pq_fmd.c)
target_link_libraries(test_pq_fmd pq_fmd) # gsl gslcblas m
