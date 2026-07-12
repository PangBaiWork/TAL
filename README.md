# tal

Native build workspace for TraceAnyLoc/TAL.

## Repository Setup

Clone with submodules and Git LFS objects:

```sh
git clone --recurse-submodules <repo-url> tal
cd tal
git lfs pull
```

If the repository was cloned without submodules:

```sh
git submodule update --init --recursive
git lfs pull
```

The large Frida Gum static libraries are tracked through Git LFS:

- `libs/frida-gum/android/libfrida-gum.a`
- `libs/frida-gum/linux/libfrida-gum.a`
- `libs/frida-gum/windows/frida-gum.lib`

The source dependencies kept as submodules are:

- `Triton`: official upstream Triton checkout.
- `qbdi-src`: QBDI source checkout.
- `Release`: release/test asset repository. Its internal changes belong to that repository, not to this root repository.

## Build

The project is configured through CMake presets. Generated files and build outputs are kept under `build/`.

Android arm64:

```sh
export ANDROID_NDK=/path/to/android-ndk
cmake --preset android-arm64-release
cmake --build --preset android-arm64-release
```

The helper script can discover the Android NDK from `ANDROID_NDK`, `ANDROID_HOME`, or `ANDROID_SDK_ROOT`:

```sh
scripts/build-android.sh
```

Linux x86_64:

```sh
cmake --preset linux-ninja-release
cmake --build --preset linux-ninja-release
```

Windows x64, from a Visual Studio developer shell:

```bat
cmake --preset windows-vs2022-release
cmake --build --preset windows-vs2022-release
```

## Host Tools

QBDI may build native LLVM table-generation tools while cross-compiling. Use a normal host compiler, such as `gcc`, `clang`, or MSVC.

For explicit host tool selection:

```sh
export TAL_HOST_CC=/path/to/cc
export TAL_HOST_CXX=/path/to/c++
export TAL_HOST_AR=/path/to/ar
export TAL_HOST_RANLIB=/path/to/ranlib
```

## Boost Lite

`third_party/boost-lite` is a BCP-trimmed Boost subset used to reduce configure and build cost. Regenerate it only when Boost includes used by TAL change:

```sh
cmake -DBOOST_SOURCE_DIR=/path/to/boost-1.90.0 \
      -DBCP_EXECUTABLE=/path/to/bcp \
      -P cmake/UpdateBoostLite.cmake
```

The x64 smoke test for the trimmed Boost tree is:

```sh
cd test/boost-lite-x64
cmake --preset x64-release
cmake --build --preset x64-release
ctest --preset x64-release
```

## Capstone

Do not add a separate Capstone checkout. TAL uses the Capstone headers and symbols bundled with Frida Gum through the compatibility headers in `third_party/frida-capstone`.
