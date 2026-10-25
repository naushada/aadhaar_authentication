# uidai-cpp

C++17 port of the UIDAI Aadhaar authentication client (AUA/ASA) — OTP, Auth and
eKYC — using **libevent** for the socket layer and **OpenSSL** for crypto, built
with **CMake**. See [`DESIGN.md`](DESIGN.md) for the full spec.

Three build paths are supported:

1. **Native CMake** — the fast development/test loop on macOS (`arm64` /
   `x86_64`) or desktop Linux.
2. **Podman** — produce Linux ELF binaries (x86_64 and/or arm64) in a
   container, no cross toolchain on the host.
3. **Yocto** — the real target build for ARM Linux devices, via a `meta-uidai`
   layer that wraps CMake with the cross toolchain + sysroot.

## Layout

```
cpp/
├── CMakeLists.txt
├── Containerfile                      # Podman/Docker Linux build
├── .containerignore
├── cmake/FindLibevent.cmake           # libevent finder (uidai::libevent target)
├── include/uidai/{core,transport,protocol}/
├── src/{core,transport,protocol}/ + cli.cpp
├── yocto/meta-uidai/                  # Yocto layer + recipe
└── DESIGN.md
```

## 1. Native CMake build

Requirements: CMake ≥ 3.16, OpenSSL (1.1.1+ or 3.x), libevent 2.1.

### macOS (Homebrew)

```sh
brew install cmake libevent openssl@3

cmake -S . -B build \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" \
  -DLIBEVENT_ROOT_DIR="$(brew --prefix libevent)"

cmake --build build -j
./build/uidai_cli
```

On Apple Silicon this produces an `arm64` binary; on Intel it produces `x86_64`.
Pass `-DCMAKE_OSX_ARCHITECTURES=x86_64` (or `arm64`) to cross between the two
from one machine.

### Desktop Linux (native)

```sh
sudo apt install build-essential cmake libssl-dev libevent-dev
cmake -S . -B build
cmake --build build -j
```

## 2. Podman build (Linux container)

Build a Linux ELF without installing a cross toolchain on the host. Build
context is the `cpp/` directory:

```sh
podman build -t uidai-cpp .
podman run --rm uidai-cpp
```

Multi-arch — e.g. `linux/arm64` on an Apple Silicon podman machine (via qemu
binfmt emulation) — pass `--platform`:

```sh
podman build --platform linux/arm64 -t uidai-cpp:arm64 .
podman run --rm uidai-cpp:arm64
```

The `Containerfile` is two-stage: it builds in a `debian:bookworm` image with
`cmake g++ libssl-dev libevent-dev`, then copies `uidai_cli` into a slim runtime
image with only `libssl3` + `libevent`.

## 3. Yocto build (ARM Linux target)

Yocto supplies the cross toolchain *and* a sysroot containing OpenSSL and
libevent via their recipes — no hand-rolled toolchain or sysroot needed.

### Add the layer

In your `build/conf/bblayers.conf`:

```
BBLAYERS ?= " \
  ... \
  /path/to/aadhaar_authentication/cpp/yocto/meta-uidai \
"
```

### Build it

```sh
bitbake uidai-cpp
```

The recipe (`uidai-cpp_git.bb`) inherits `cmake` + `pkgconfig`, depends on
`openssl` and `libevent`, and builds the `cpp/` subdirectory. `FindLibevent.cmake`
locates libevent inside the sysroot via Yocto's `CMAKE_FIND_ROOT_PATH`.

### Local development with `externalsrc` (no git push)

For iterate-on-source builds, add to `build/conf/local.conf`:

```
INHERIT += "externalsrc"
EXTERNALSRC:pn-uidai-cpp = "/path/to/aadhaar_authentication/cpp"
EXTERNALSRC_BUILD:pn-uidai-cpp = "/path/to/aadhaar_authentication/cpp/build-yocto"
```

Then `bitbake uidai-cpp` builds straight from your working tree.

## 4. Milestones

| Mx | Deliverable |
|----|-------------|
| M0 | CMake + empty libs, link OpenSSL + libevent, Logger, native + Podman + Yocto build |
| M1 | Crypto engine + XML builder/signature (golden-tested) |
| M2 | libevent transport (bufferevent, chunked decoder, EventLoop) |
| M3 | OTP v1.6 strategy |
| M4 | Auth v2.0 strategy |
| M5 | eKYC strategy |
| M6 | Remaining protocol versions (v2.1, v2.5) |
| M7 | GUI |

## 5. Testing

Unit tests are off by default:

```sh
cmake -S . -B build -DUIDAI_BUILD_TESTS=ON ...
cmake --build build
ctest --test-dir build --output-on-failure
```

Golden-file tests compare against byte-exact fixtures (see DESIGN.md §15 for the
volatile-field normalization rules).
