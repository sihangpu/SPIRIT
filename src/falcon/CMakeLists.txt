
 # For post-quantum FMD tracking

 cmake_minimum_required(VERSION 3.13)

 if(MSVC)
  add_compile_options(/nologo /O2 /W4 /wd4146 /wd4244)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
  # add_compile_options(-Werror)
  add_compile_options(-Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith)
  add_compile_options(-O3 -fomit-frame-pointer)
 
endif()


set(FALCON_SRCS codec.c common.c falcon.c fft.c fpr.c keygen.c rng.c shake.c sign.c vrfy.c)



add_library(falcon ${FALCON_SRCS} )
target_link_libraries(falcon crypto)
