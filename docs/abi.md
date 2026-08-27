# ABI Contract

## Approved shared-library surface

`abi/approved-symbols.txt` is the source of truth for the C8-B shared-library
surface. The shared target is built with hidden visibility; only declarations
that opt into the public API visibility and appear in the approved list are
exported. Internal queue, persistent-store, hash, protocol, signing,
compression, and adapter implementation symbols are not part of this ABI.

The approved surface is grouped as follows:

- allocator hooks and the malloc/calloc/realloc/free/strdup and secure cleanup helpers;
- environment init/destroy, error field cleanup, HTTP response init, retry init/next, and the default platform initializer;
- every externally callable function declared by `ve_tls_producer.h`;
- the versioned config initializer and producer constructor in the 0.3.0 API;
- the legacy and versioned Android config binding entry points plus the three lifecycle helpers;
- `ve_tls_http_client_init_curl` only when `VE_TLS_ENABLE_CURL=ON`.

The linker export list and `cmake/verify_exports.cmake` enforce the same
allow-list. The check uses Mach-O `nm -gU` on macOS and ELF `nm -D
--defined-only --extern-only` elsewhere. A shared build must pass the
`ve_tls_abi_exports` CTest before it is released.

The install package contains only the approved ABI headers and their
transitive type dependencies. Source-tree headers for protocol, signing,
hashing, compression, and the legacy adapter are internal implementation
interfaces; they are neither installed nor supported as shared-library ABI.

The bundled static LZ4 copy is compiled with the private `VE_TLS_LZ4_*`
namespace. The build-time symbol check rejects any defined bare `LZ4_*`
symbol, and a consumer link test verifies coexistence with host-provided bare
LZ4 symbols. The private prefixed symbols are implementation details and are
not added to `abi/approved-symbols.txt`.

The 0.3.0 shared release gate supports Mach-O and ELF targets, including
Android ELF. Windows is not a supported build target for this POSIX/mobile
core release. The Windows branch of `VE_TLS_API` preserves header portability
for a future platform adapter, but is not DLL compatibility evidence.

## Versioning

The 0.3.0 headers define `VE_TLS_C_SDK_VERSION` and
`VE_TLS_C_SDK_API_VERSION` as `"0.3.0"`. Consumers should compile against the
installed headers and use the versioned constructor when selecting an explicit
API contract. Symbol presence alone does not make a structure layout or a
callback ABI compatible; the size/version contract and the target-platform
layout must also match.

`ve_tls_config_init` and `ve_tls_producer_create` retain the pre-versioned
layout through `VE_TLS_CONFIG_LEGACY_SIZE`; they do not consume any versioned
tail. Version 1 ends after `persistent_durability` and uses the exact
`VE_TLS_CONFIG_VERSION_1_SIZE`. Version 2 appends persistent max-age and
authentication-failure policy fields and uses `sizeof(ve_tls_config)`.
Consumers must pair `ve_tls_config_init_versioned` with
`ve_tls_producer_create_versioned` and pass the exact size for the selected
version. Size or version mismatches fail without reading beyond that layout.

The same rule applies to the Android bridge. The legacy
`ve_tls_android_binding_build_config` consumes only
`VE_TLS_ANDROID_CONFIG_VIEW_V1_SIZE`. Current Android integrations use
`ve_tls_android_binding_build_config_versioned` with the complete view size and
`VE_TLS_ANDROID_CONFIG_VIEW_VERSION_CURRENT`, plus the output config size and
`VE_TLS_CONFIG_VERSION_CURRENT`. This keeps the original destroy and HTTP
bridge offsets stable while making both input and output layouts explicit.

## Record-layout baselines

The following are release baselines, not cross-platform promises. Each entry is
`sizeof / alignment` in bytes and was obtained from clang record-layout dumps
or the corresponding baseline snapshot.

| Target | config V1 prefix | config V2 | `ve_tls_platform` | `ve_tls_android_config_view` |
| --- | ---: | ---: | ---: | ---: |
| macOS arm64, clang | 744 / 8 | 760 / 8 | 208 / 8 | 240 / 8 |
| Android NDK r21.4, armeabi-v7a API19 | 512 / 8 | 528 / 8 | 104 / 4 | 180 / 4 |
| Android NDK r21.4, arm64-v8a API21 | 744 / 8 | 760 / 8 | 208 / 8 | 240 / 8 |
| Android NDK r21.4, x86 API19 | 504 / 4 | 520 / 4 | 104 / 4 | 180 / 4 |
| Android NDK r21.4, x86_64 API21 | 744 / 8 | 760 / 8 | 208 / 8 | 240 / 8 |

In particular, the two 32-bit Android rows are not interchangeable. For V2,
`armeabi-v7a` has size 528 with alignment 8, while x86 has size 520 with
alignment 4. Do not hard-code any row as a universal value.

The ABI acceptance rule is `sizeof`/alignment plus the API version contract and
a fresh record-layout dump for every supported platform and compiler
combination. Build logs are release evidence, not stable paths in this source
tree.
