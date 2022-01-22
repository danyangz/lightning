cmake_minimum_required(VERSION 3.10)

project(Lightning)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lrt")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

set(SRC_DIR "${PROJECT_SOURCE_DIR}/src")
include_directories("${PROJECT_SOURCE_DIR}/inc")

file(GLOB LIB_SRC
  "${SRC_DIR}/log_disk.cc"
  "${SRC_DIR}/malloc.cc"
  "${SRC_DIR}/object_log.cc"
)

add_library(lightning STATIC ${LIB_SRC})
target_link_libraries(lightning "-lrt -lpthread")

add_executable(store "${SRC_DIR}/store.cc")
target_link_libraries(store lightning)

file(GLOB TEST_SRC
  "${PROJECT_SOURCE_DIR}/test/*.cc"
)

foreach(test_file ${TEST_SRC})
  get_filename_component(prog_name ${test_file} NAME_WE)
  add_executable(${prog_name} "${SRC_DIR}/client.cc" ${test_file})
  target_link_libraries(${prog_name} lightning)
endforeach(test_file ${TEST_SRC})

option(VERIFIER "Build the verifier" OFF)

if (VERIFIER)

foreach(src_file ${LIB_SRC} "${SRC_DIR}/client.cc" "${SRC_DIR}/store.cc")
  get_filename_component(prog_name ${src_file} NAME_WE)
  execute_process (
    COMMAND bash -c "clang++-6.0 -I${PROJECT_SOURCE_DIR}/inc -g -S -emit-llvm -o ${prog_name}.ll ${SRC_DIR}/${prog_name}.cc"
  )
endforeach(src_file ${LIB_SRC} "${SRC_DIR}/client.cc" "${SRC_DIR}/store.cc")

add_subdirectory(verifier)

endif (VERIFIER)

option(JAVA_CLIENT "Build the Java client" OFF)

if (JAVA_CLIENT)
find_package(JNI REQUIRED)
include_directories(${JNI_INCLUDE_DIRS})

add_library(jlightning SHARED ${LIB_SRC} "${SRC_DIR}/client.cc" "${PROJECT_SOURCE_DIR}/java/JlightningClient.cc")
target_link_libraries(jlightning "-lrt -lpthread")

endif (JAVA_CLIENT)
