#pragma once
#include "types.h"

const uint8_t *pe_export_addr(
	const uint8_t *module, uintptr_t filesize, const char *funcname
);
const uint8_t *pe_section_bounds(
	const uint8_t *module, uintptr_t *size, uint8_t *ptr
);
const uint8_t *pe_load_file(
	const wchar_t * filepath
);
void fix_reloc_table(
	const uint8_t * module, const uint8_t * ori_img_base
);
uint8_t * get_module_base(
	const PDRIVER_OBJECT drv_obj, const wchar_t *name
);