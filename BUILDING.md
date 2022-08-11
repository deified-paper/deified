# Configuration

Adjust the definitions of the macros in the `include/config.h` file.

# Instructions

1. Modify the script to adjust configuration options as desired, then execute it to install all dependencies and configure the system:

```
nano ./scripts/setup.sh
sudo ./scripts/setup.sh
```

## DeiFIed

1. Select an interface to use for communication between the runtime and verifier:

* `MODEL`: Models the behavior of AppendWrite in software using a [POSIX shared memory](http://man7.org/linux/man-pages/man7/shm_overview.7.html) interface (`/dev/shm/HQ`). For performance testing only; messages are not actually append-only.

2. Build or download our modified LLVM compiler toolchain. See [setup instructions below](#compiler-clangllvm).

4. Build and compile the DeiFIed framework, including compiler instrumentation, runtime library, and verifier application, as follows. To support inlining our messaging interface, also pass `-DBUILD_RTLIB_INLINE=ON` to CMake, but this is not compatible with all interfaces.

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=$CLANG_HQ/lib/cmake/llvm -DINTERFACE=<interface> ..
make
export BUILD_PATH=`pwd`
export CFLAGS_CFI+=" -fplugin=$BUILD_PATH/llvm/libcfi.so"
export CFLAGS_DFI+=" -fplugin=$BUILD_PATH/llvm/libdfi.so"
export LDFLAGS_CFI+=" -Wl,-z,now -Wl,-z,relro -fplugin=$BUILD_PATH/llvm/libcfi.so"
export LDFLAGS_DFI+=" -Wl,-z,now -Wl,-z,relro -fplugin=$BUILD_PATH/llvm/libdfi.so"
```

5. Build our modified standard runtime libraries. See [setup instructions below](#standard-runtimes-musl-libstdc).

6. Initialize the interface and execute the verifier. See [setup instructions below](#verifier).

7. Build and execute applications. See [setup instructions below](#applications).

## Compiler (Clang/LLVM)

1. Obtain our modified Clang/LLVM compiler toolchain, which supports plugin passes during LTO, includes additional optimizations, does not discard value names and lifetime markers, and is configured with a default target triple and system root directory for musl cross-compilation. Either:

* Use the pre-built binaries under GitHub Releases, and extract to e.g. `llvm/llvm-project/llvm/build_release`.
* Build the `llvm-project` submodule from source, as follows:

```
cd llvm/llvm-project/llvm
mkdir build_release
cd build_release
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLLVM_CCACHE_BUILD=ON -DLLVM_BINUTILS_INCDIR=/usr/include -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_ENABLE_RUNTIMES=compiler-rt -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_DEFAULT_TARGET_TRIPLE=x86_64-alpine-linux-musl -DDEFAULT_SYSROOT=/opt/cross -DLLVM_USE_LINKER=gold -DLLVM_CCACHE_BUILD=ON -DLLVM_OPTIMIZED_TABLEGEN=ON -DLLVM_LINK_LLVM_DYLIB=ON -DLLVM_USE_SPLIT_DWARF=ON -DLLVM_USE_GDB_INDEX=ON -DLLVM_ENABLE_DUMP=ON -GNinja ..
ninja
```

2. Set the appropriate environment variables to refer to the original and modified Clang/LLVM compiler toolchains:

```
export CLANG_NONE="clang-10"
export CLANGXX_NONE="clang++-10"

export CLANG_HQ="<llvm path>"
export CLANG_CFI="$CLANG_HQ/bin/clang"
export CLANGXX_CFI="$CLANG_HQ/bin/clang++"
```

## Standard Runtimes (musl, libstdc++)

1. Obtain a cross-compile environment that uses the musl C runtime library, either:

* Use the pre-built [Alpine Linux](https://alpinelinux.org/) filesystem under GitHub Releases, and extract to `/opt/cross/x86_64-alpine-linux-musl`.
* Build the `musl-cross-make` and `musl` submodules from source, as follows:

```
cd rtlib/musl-cross-make
make
sudo make install
sudo rm -r /opt/cross/x86_64-alpine-linux-musl/include
cd /opt/cross/x86_64-alpine-linux-musl
sudo ln -s ../include include
sudo ln -s /usr/include/sys/queue.h include/sys/queue.h
```

2. Create a copy of this cross-compile environment for baseline experiments, and configure it:

```
sudo cp -r /opt/cross /opt/cross-none
sudo ln -s /opt/cross-none/x86_64-alpine-linux-musl/lib/libc.so /lib/ld-musl-x86_64.so.1
echo -e "/opt/cross-none/x86_64-alpine-linux-musl/lib\n/opt/cross-none/x86_64-alpine-linux-musl/usr/lib" | sudo tee /etc/ld-musl-x86_64.path
```

3. Create the instrumented cross-compile environment, by rebuilding the musl C runtime library with the DeiFIed runtime library and system call instrumentation, overwriting the uninstrumented one, and configuring it:

```
cd rtlib/musl
mkdir build
cd build
CC=$CLANG_CFI CXX=$CLANGXX_CFI CFLAGS+=" -fplugin=$BUILD_PATH/llvm/libhq.so" LDFLAGS+=" -L$BUILD_PATH/rtlib -Wl,--whole-archive -lrtlib -Wl,--no-whole-archive" ../configure
make
sudo cp lib/libc.so /opt/cross/x86_64-alpine-linux-musl/lib/ld-musl-x86_64-hq.so.1
sudo ln -s /opt/cross/x86_64-alpine-linux-musl/lib/ld-musl-x86_64-hq.so.1 /lib/ld-musl-x86_64-hq.so.1
echo -e "/opt/cross/x86_64-alpine-linux-musl/lib\n/opt/cross/x86_64-alpine-linux-musl/usr/lib" | sudo tee /etc/ld-musl-x86_64-hq.path
```

## Verifier

1. Load the DeiFIed kernel interface:

```
sudo insmod kernel/hq.ko
```

2. Execute the verifier:

```
sudo ./verifier/verifier
```

## Applications

1. Set the compiler flags for building applications, as shown below. Certain variables are used only to build the baseline (`CLANG_NONE`, `CLANGXX_NONE`, `CFLAGS_NONE`, `LDFLAGS_NONE`), whereas others are used to build with DeiFIed and DFI (`CFLAGS_DFI`, `LDFLAGS_DFI`). Devirtualization optimizations can be enabled by expanding the `OPT` variable when building. Inlining of the messaging interface can enabled by setting the variable `HQ_INLINE_PATH`: `export HQ_INLINE_PATH=$BUILD_PATH/rtlib/rtlib_msg.o`.

```
export OPT+=" -fstrict-vtable-pointers -fforce-emit-vtables -fvirtual-function-elimination -fwhole-program-vtables"

export CFLAGS_NONE+=" --target=x86_64-alpine-linux-musl --sysroot=/opt/cross-none --gcc-toolchain=/opt/cross-none -flto -fvisibility=hidden"
export LDFLAGS_NONE+=" -Wl,-z,now -Wl,-z,relro --target=x86_64-alpine-linux-musl --sysroot=/opt/cross-none --gcc-toolchain=/opt/cross-none -flto -fuse-ld=gold -Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1"

export CFLAGS_DFI+=" -flto -fvisibility=hidden"
export LDFLAGS_DFI+=" -flto -fuse-ld=gold -fsanitize=safe-stack"
```

### Chromium

1. Clone the [Chromium](https://github.com/deified-paper/chromium) repository.
2. Follow the [build instructions](https://chromium.googlesource.com/chromium/src/+/master/docs/linux/build_instructions.md) only to setup depot_tools and install additional build dependencies.
3. Add our fork of `libcxx`:
```
cd buildtools/third_party/libc++/trunk
git remote add fork git@github.com:deified-paper/libcxx.git
git fetch
```
4. Run `gclient sync`.
5. Apply the bundled patch for musl compatibility using `patch -p2 < musl.diff`.
6. Configure a build using `gn gen <path>`, copy in the contents of `args.gn`, and set the variable `is_debug=false` if a debug build is not desired.
7. After the build is complete, increase the open file descriptor limit with `ulimit -n 8192`, then run the browser with `./chrome --use-gl=desktop --start-maximized`.
