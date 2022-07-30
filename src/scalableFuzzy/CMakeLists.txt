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


 add_library(scalable_fuzzy_tracking_20_10 ${SCALABLE_FUZZY_SRCS})
 target_compile_definitions(scalable_fuzzy_tracking_20_10 PUBLIC USERS_NUM_E=20 FUZZY_LIST_SIZE_E=10)
 target_link_libraries(scalable_fuzzy_tracking_20_10)

 add_library(scalable_fuzzy_tracking_20_12 ${SCALABLE_FUZZY_SRCS})
 target_compile_definitions(scalable_fuzzy_tracking_20_12 PUBLIC USERS_NUM_E=20 FUZZY_LIST_SIZE_E=12)
 target_link_libraries(scalable_fuzzy_tracking_20_12)

 add_library(scalable_fuzzy_tracking_30_15 ${SCALABLE_FUZZY_SRCS})
 target_compile_definitions(scalable_fuzzy_tracking_30_15 PUBLIC USERS_NUM_E=30 FUZZY_LIST_SIZE_E=15)
 target_link_libraries(scalable_fuzzy_tracking_30_15)

 add_executable(test_scalable_fuzzy_20_10  test/test_scalable_fuzzy.c)
 target_link_libraries(test_scalable_fuzzy_20_10 scalable_fuzzy_tracking_20_10)

 add_executable(test_scalable_fuzzy_20_12  test/test_scalable_fuzzy.c)
 target_link_libraries(test_scalable_fuzzy_20_12 scalable_fuzzy_tracking_20_12)

 add_executable(test_scalable_fuzzy_30_15  test/test_scalable_fuzzy.c)
 target_link_libraries(test_scalable_fuzzy_30_15 scalable_fuzzy_tracking_30_15)
