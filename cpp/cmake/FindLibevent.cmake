# FindLibevent.cmake — locate libevent_core and expose the imported target
# uidai::libevent.
#
# Influenced by:
#   -DLIBEVENT_ROOT_DIR=/path/to/prefix   (native, e.g. /opt/homebrew/opt/libevent)
#   env LIBEVENT_ROOT_DIR                 (also picked up)
# Under Yocto, CMAKE_FIND_ROOT_PATH points into the sysroot, so find_path /
# find_library locate the cross-built libevent automatically.

find_path(LIBEVENT_INCLUDE_DIR
  NAMES event2/event.h
  HINTS ${LIBEVENT_ROOT_DIR} ENV LIBEVENT_ROOT_DIR
  PATH_SUFFIXES include)

find_library(LIBEVENT_LIBRARY
  NAMES event_core
  HINTS ${LIBEVENT_ROOT_DIR} ENV LIBEVENT_ROOT_DIR
  PATH_SUFFIXES lib lib64)

# libevent's OpenSSL bufferevent backend (bufferevent_openssl_*), needed for the
# HTTPS transport.
find_library(LIBEVENT_OPENSSL_LIBRARY
  NAMES event_openssl
  HINTS ${LIBEVENT_ROOT_DIR} ENV LIBEVENT_ROOT_DIR
  PATH_SUFFIXES lib lib64)

# The HTTPS transport creates SSL objects with OpenSSL and hands them to
# libevent_openssl (bufferevent_openssl_socket_new). Those objects must be
# allocated by the *same* OpenSSL libevent_openssl was linked against, or the
# internal struct layouts differ and bufferevent_openssl_socket_new crashes.
# Homebrew, for example, builds libevent against openssl@4 while
# find_package(OpenSSL) may otherwise pick openssl@3. On macOS, read the dylib's
# install-name dependencies and pin OpenSSL to the matching prefix. This is
# unconditional on purpose: a mismatched OpenSSL is a guaranteed crash, so there
# is nothing to override.
if(APPLE AND LIBEVENT_OPENSSL_LIBRARY)
  execute_process(COMMAND otool -L "${LIBEVENT_OPENSSL_LIBRARY}"
    OUTPUT_VARIABLE _uidai_otool OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  # e.g. ".../openssl@4/lib/libssl.4.dylib" -> prefix ".../openssl@4"
  string(REGEX MATCH "[^\n\t ]*/libssl\\.[0-9.]+" _uidai_ssl "${_uidai_otool}")
  if(_uidai_ssl)
    get_filename_component(_uidai_ssl_libdir "${_uidai_ssl}" DIRECTORY)
    get_filename_component(_uidai_ssl_prefix "${_uidai_ssl_libdir}" DIRECTORY)
    if(EXISTS "${_uidai_ssl_prefix}/include/openssl/ssl.h")
      set(OPENSSL_ROOT_DIR "${_uidai_ssl_prefix}" CACHE PATH
        "OpenSSL prefix that libevent_openssl links against" FORCE)
      # Drop any cached FindOpenSSL results so find_package(OpenSSL) re-searches
      # with the pinned prefix; a stale cache (e.g. a prior openssl@3 configure)
      # would otherwise keep linking the old libraries.
      unset(OPENSSL_SSL_LIBRARY CACHE)
      unset(OPENSSL_CRYPTO_LIBRARY CACHE)
      unset(OPENSSL_INCLUDE_DIR CACHE)
    endif()
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libevent
  REQUIRED_VARS LIBEVENT_LIBRARY LIBEVENT_OPENSSL_LIBRARY LIBEVENT_INCLUDE_DIR)

if(Libevent_FOUND AND NOT TARGET uidai::libevent)
  add_library(uidai::libevent UNKNOWN IMPORTED)
  set_target_properties(uidai::libevent PROPERTIES
    IMPORTED_LOCATION "${LIBEVENT_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBEVENT_INCLUDE_DIR}")
endif()

if(Libevent_FOUND AND NOT TARGET uidai::libevent_openssl)
  add_library(uidai::libevent_openssl UNKNOWN IMPORTED)
  set_target_properties(uidai::libevent_openssl PROPERTIES
    IMPORTED_LOCATION "${LIBEVENT_OPENSSL_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBEVENT_INCLUDE_DIR}")
endif()
