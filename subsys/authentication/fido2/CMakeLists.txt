# SPDX-License_Identifier: Apache-2.0

zephyr_library_sources(
  fido2_core.c
  fido2_cbor.c
  fido2_crypto.c
)

add_subdirectory(attestation)
add_subdirectory(storage)
add_subdirectory(transport)
