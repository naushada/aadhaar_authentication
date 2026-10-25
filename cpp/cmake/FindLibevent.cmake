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

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libevent
  REQUIRED_VARS LIBEVENT_LIBRARY LIBEVENT_INCLUDE_DIR)

if(Libevent_FOUND AND NOT TARGET uidai::libevent)
  add_library(uidai::libevent UNKNOWN IMPORTED)
  set_target_properties(uidai::libevent PROPERTIES
    IMPORTED_LOCATION "${LIBEVENT_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBEVENT_INCLUDE_DIR}")
endif()
