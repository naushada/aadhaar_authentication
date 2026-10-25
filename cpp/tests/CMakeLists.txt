add_executable(uidai_tests
  test_main.cpp
  crypto_engine_test.cpp
  key_store_test.cpp
  xml_signature_test.cpp
  transport_test.cpp
  otp_test.cpp
  auth_test.cpp
  ekyc_test.cpp)

target_include_directories(uidai_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(uidai_tests PRIVATE uidai_core uidai_transport uidai_protocol)

# Golden XML fixtures (otp_success.xml etc.) and demo keys live one level above
# cpp/ (the repo root). Expose that path so golden tests are self-contained.
target_compile_definitions(uidai_tests PRIVATE
  UIDAI_REPO_ROOT="${CMAKE_SOURCE_DIR}/..")

add_test(NAME uidai_tests COMMAND uidai_tests)
