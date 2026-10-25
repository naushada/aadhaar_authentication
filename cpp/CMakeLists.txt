cmake_minimum_required(VERSION 3.16)
project(uidai_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Emit build/compile_commands.json so clangd/editors resolve includes.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Our finder (FindLibevent.cmake) lives here.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(OpenSSL REQUIRED)
find_package(Libevent REQUIRED)

option(UIDAI_BUILD_CLI   "Build the uidai_cli driver" ON)
option(UIDAI_BUILD_TESTS "Build unit tests"          OFF)

# ---- uidai_core: core + crypto + xml (OpenSSL is consumed here) ----
add_library(uidai_core STATIC
  src/core/logger.cpp
  src/crypto/crypto_engine.cpp
  src/crypto/key_store.cpp
  src/xml/xml_signature.cpp)
target_include_directories(uidai_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(uidai_core PUBLIC OpenSSL::Crypto)

# The port deliberately reproduces a few byte-exact but deprecated OpenSSL
# calls (X509_NAME_oneline, X509_get0_pubkey's older sibling) that the UIDAI
# XML formatting depends on; silence those warnings, keep everything else.
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(uidai_core PRIVATE -Wno-deprecated-declarations)
endif()

# ---- uidai_transport: libevent socket / http ----
add_library(uidai_transport STATIC
  src/transport/transport.cpp
  src/transport/http.cpp
  src/transport/chunked.cpp
  src/transport/event_loop.cpp)
target_include_directories(uidai_transport PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(uidai_transport PUBLIC uidai::libevent)

# ---- uidai_protocol: otp / auth / ekyc strategies ----
add_library(uidai_protocol STATIC
  src/protocol/protocol.cpp
  src/protocol/otp.cpp
  src/protocol/auth.cpp)
target_include_directories(uidai_protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(uidai_protocol PUBLIC uidai_core)

if(UIDAI_BUILD_CLI)
  add_executable(uidai_cli src/cli.cpp)
  target_link_libraries(uidai_cli PRIVATE uidai_core uidai_transport uidai_protocol)
endif()

if(UIDAI_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
