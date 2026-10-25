SUMMARY = "UIDAI Aadhaar authentication client (C++17 port)"
DESCRIPTION = "AUA/ASA client for UIDAI OTP, Auth and eKYC, ported from C to \
C++17 on libevent, built with CMake."
HOMEPAGE = "https://example.com/uidai-cpp"
LICENSE = "CLOSED"

# CMake project + OpenSSL (crypto) + libevent, plus pkgconfig for recipe deps.
inherit cmake pkgconfig

DEPENDS = "openssl libevent"

# Replace with your real remote. For local development, prefer externalsrc
# (see the README "Yocto" section) instead of editing SRC_URI here.
SRC_URI = "git://git.example.com/yourorg/uidai-cpp.git;protocol=https;branch=master"
SRCREV = "${AUTOREV}"
PV = "0.1.0+git${SRCPV}"

# The CMakeLists.txt lives in the cpp/ subdirectory of the repo.
S = "${WORKDIR}/git/cpp"

EXTRA_OECMAKE = "-DUIDAI_BUILD_CLI=ON -DUIDAI_BUILD_TESTS=OFF"
