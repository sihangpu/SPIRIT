 # For ScalableFuzzy Tracking

 cmake_minimum_required(VERSION 3.13)

 if(MSVC)
  add_compile_options(/nologo /O2 /W4 /wd4146 /wd4244)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
  add_compile_options(-Werror)
  add_compile_options(-Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith)
  add_compile_options(-O3 -fomit-frame-pointer)
 
endif()

 
 set(SCALABLE_FUZZY_SRCS pack_unpack.c poly.c fips202.c cbd.c indcpa.c scalableFuzzy.c poly_mul.c randombytes.c)


 add_library(scalable_fuzzy_tracking ${SCALABLE_FUZZY_SRCS})
 target_compile_definitions(scalable_fuzzy_tracking PUBLIC FUZZY_LIST_SIZE_E=10)
 target_link_libraries(scalable_fuzzy_tracking)

 add_executable(test_scalable_fuzzy  test/test_scalable_fuzzy.c)
 target_link_libraries(test_scalable_fuzzy scalable_fuzzy_tracking)
