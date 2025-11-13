cmake_minimum_required(VERSION 3.16)
project(fixlat-kfifo-ipfilter C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_BUILD_TYPE Release)

find_program(CLANG clang REQUIRED)
find_program(BPFTOOL bpftool REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

include_directories(${CMAKE_SOURCE_DIR}/include)

set(BPF_SRC ${CMAKE_SOURCE_DIR}/bpf/fixlat.bpf.c)
set(BPF_OBJ ${CMAKE_BINARY_DIR}/fixlat.bpf.o)
set(SKEL_H  ${CMAKE_BINARY_DIR}/user/fixlat.skel.h)

add_custom_command(
  OUTPUT ${BPF_OBJ}
  COMMAND ${CLANG} -g -O2 -target bpf -D __TARGET_ARCH_x86 -I${CMAKE_SOURCE_DIR}/include -c ${BPF_SRC} -o ${BPF_OBJ}
  DEPENDS ${BPF_SRC} ${CMAKE_SOURCE_DIR}/include/fixlat.h
  VERBATIM)

add_custom_command(
  OUTPUT ${SKEL_H}
  COMMAND ${BPFTOOL} gen skeleton ${BPF_OBJ} > ${SKEL_H}
  DEPENDS ${BPF_OBJ}
  VERBATIM)

add_custom_target(bpf_skel ALL DEPENDS ${SKEL_H})

add_executable(fixlat user/fixlat.c ${SKEL_H})
add_dependencies(fixlat bpf_skel)
target_include_directories(fixlat PRIVATE ${CMAKE_BINARY_DIR}/user)
target_link_libraries(fixlat ${LIBBPF_LIBRARIES})
target_link_directories(fixlat PRIVATE ${LIBBPF_LIBRARY_DIRS})
target_compile_options(fixlat PRIVATE ${LIBBPF_CFLAGS_OTHER})
