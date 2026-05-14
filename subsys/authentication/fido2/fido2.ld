#include <zephyr/linker/iterable_sections.h>

ITERABLE_SECTION_ROM(fido2_transport, Z_LINK_ITERABLE_SUBALIGN)
ITERABLE_SECTION_ROM(fido2_uv, Z_LINK_ITERABLE_SUBALIGN)
