#include <fltkernel.h>
#include <ntimage.h>
#include "struct.h"
#include "pe.h"

static const uint8_t *rva_to_ptr(
	IMAGE_NT_HEADERS *image_nt_headers, uintptr_t rva,
	const uint8_t *module, uintptr_t filesize
) {
	IMAGE_SECTION_HEADER *image_section_header =
		IMAGE_FIRST_SECTION(image_nt_headers);

	uint32_t idx, section_count =
		image_nt_headers->FileHeader.NumberOfSections;

	for (idx = 0; idx < section_count; idx++, image_section_header++) {
		uintptr_t va = image_section_header->VirtualAddress;
		if (rva >= va && rva < va + image_section_header->Misc.VirtualSize) {
			rva += image_section_header->PointerToRawData - va;
			return rva < filesize ? module + rva : NULL;
		}
	}
	return NULL;
}

static int32_t rva_to_section(
	IMAGE_NT_HEADERS *image_nt_headers, uintptr_t rva
) {
	IMAGE_SECTION_HEADER *image_section_header =
		IMAGE_FIRST_SECTION(image_nt_headers);

	uint32_t idx, section_count =
		image_nt_headers->FileHeader.NumberOfSections;

	for (idx = 0; idx < section_count; idx++, image_section_header++) {
		uintptr_t va = image_section_header->VirtualAddress;
		if (rva >= va && rva < va + image_section_header->Misc.VirtualSize) {
			return idx;
		}
	}
	return -1;
}

const uint8_t *pe_export_addr(
	const uint8_t *module, uintptr_t filesize, const char *funcname
) {
	IMAGE_DOS_HEADER *image_dos_header; IMAGE_NT_HEADERS *image_nt_headers;
	IMAGE_DATA_DIRECTORY *image_data_directory;
	IMAGE_EXPORT_DIRECTORY *image_export_directory;
	uintptr_t export_rva, export_size; uint16_t *addr_ordinals;
	uint32_t *addr_functions, *addr_names, idx, func_rva;
	const char *name;

	image_dos_header = (IMAGE_DOS_HEADER *)module;
	if (image_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	image_nt_headers =
		(IMAGE_NT_HEADERS *)(module + image_dos_header->e_lfanew);
	if (image_nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	image_data_directory = image_nt_headers->OptionalHeader.DataDirectory;

	export_rva =
		image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	export_size =
		image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	image_export_directory = (IMAGE_EXPORT_DIRECTORY *)
		rva_to_ptr(image_nt_headers, export_rva, module, filesize);
	if (image_export_directory == NULL) {
		return NULL;
	}

	addr_functions = (uint32_t *)rva_to_ptr(
		image_nt_headers, image_export_directory->AddressOfFunctions,
		module, filesize
	);
	addr_ordinals = (uint16_t *)rva_to_ptr(
		image_nt_headers, image_export_directory->AddressOfNameOrdinals,
		module, filesize
	);
	addr_names = (uint32_t *)rva_to_ptr(
		image_nt_headers, image_export_directory->AddressOfNames,
		module, filesize
	);
	if (addr_functions == NULL || addr_ordinals == NULL || addr_names == NULL) {
		return NULL;
	}

	for (idx = 0; idx < image_export_directory->NumberOfNames; idx++) {
		name = (const char *)rva_to_ptr(
			image_nt_headers, addr_names[idx], module, filesize
		);
		if (name == NULL) {
			continue;
		}

		// Ignore forwarded exports.
		func_rva = addr_functions[addr_ordinals[idx]];
		if (func_rva >= export_rva && func_rva < export_rva + export_size) {
			continue;
		}

		if (strcmp(name, funcname) == 0) {
			return rva_to_ptr(image_nt_headers, func_rva, module, filesize);
		}
	}
	return NULL;
}

const uint8_t *pe_section_bounds(
	const uint8_t *module, uintptr_t *size, uint8_t *ptr
) {
	IMAGE_DOS_HEADER *image_dos_header; IMAGE_NT_HEADERS *image_nt_headers;
	IMAGE_SECTION_HEADER *image_section_header; int32_t section;

	if (ptr < module) {
		return NULL;
	}

	image_dos_header = (IMAGE_DOS_HEADER *)module;
	if (image_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	image_nt_headers = (IMAGE_NT_HEADERS *)(
		(uint8_t *)module + image_dos_header->e_lfanew
		);
	if (image_nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	section = rva_to_section(image_nt_headers, ptr - module);
	if (section < 0) {
		return NULL;
	}

	image_section_header = IMAGE_FIRST_SECTION(image_nt_headers);
	*size = image_section_header[section].SizeOfRawData;
	return module + image_section_header[section].VirtualAddress;
}

uint8_t * get_module_base(
	const PDRIVER_OBJECT drv_obj, const wchar_t *name
) {
	PLDR_DATA_TABLE_ENTRY	data_table_entry_ptr, tmp_data_table_entry_ptr;
	PLIST_ENTRY				plist;
	UNICODE_STRING			module_name;

	RtlInitUnicodeString(&module_name, name);
	data_table_entry_ptr = (LDR_DATA_TABLE_ENTRY*)drv_obj->DriverSection;
	if (data_table_entry_ptr == NULL)
		return NULL;

	plist = data_table_entry_ptr->InLoadOrderLinks.Flink;
	while (plist != &data_table_entry_ptr->InLoadOrderLinks) {
		tmp_data_table_entry_ptr = (LDR_DATA_TABLE_ENTRY *)plist;
		if (0 == RtlCompareUnicodeString(&tmp_data_table_entry_ptr->BaseDllName, &module_name, FALSE))
			return tmp_data_table_entry_ptr->DllBase;
		plist = plist->Flink;
	}
	return NULL;
}

void fix_reloc_table(
	const uint8_t * new_module, const uint8_t * old_module
) {
	PIMAGE_DOS_HEADER img_dos_header_ptr;
	PIMAGE_NT_HEADERS img_nt_header_ptr;
	IMAGE_DATA_DIRECTORY img_data_entry;
	PIMAGE_BASE_RELOCATION img_base_relocation_ptr;
	PUSHORT type_offset_ptr;
	uintptr_t img_base;
	ULONG reloc_table_size;
	ULONG index, type, *reloc_addr;

	img_dos_header_ptr = (PIMAGE_DOS_HEADER)new_module;
	img_nt_header_ptr = (PIMAGE_NT_HEADERS)(new_module + img_dos_header_ptr->e_lfanew);
	img_base = img_nt_header_ptr->OptionalHeader.ImageBase;
	img_data_entry = img_nt_header_ptr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	img_base_relocation_ptr = (PIMAGE_BASE_RELOCATION)(new_module + img_data_entry.VirtualAddress);
	if (img_base_relocation_ptr == NULL) {
		return;
	}
	while (img_base_relocation_ptr->SizeOfBlock) {
		reloc_table_size = (img_base_relocation_ptr->SizeOfBlock - 8) / 2;
		type_offset_ptr = (PUSHORT)((uintptr_t)img_base_relocation_ptr + sizeof(IMAGE_BASE_RELOCATION));
		for (index = 0; index < reloc_table_size; index++) {
			type = type_offset_ptr[index] >> 12;
			if (type == IMAGE_REL_BASED_HIGHLOW) {
				reloc_addr = (ULONG*)((uintptr_t)(type_offset_ptr[index] & 0x0FFF) + img_base_relocation_ptr->VirtualAddress + new_module);
				if (!MmIsAddressValid(reloc_addr)) continue;
				*reloc_addr += (ULONG)((uintptr_t)old_module - img_base);
			}
		}

		img_base_relocation_ptr = (PIMAGE_BASE_RELOCATION)((uintptr_t)img_base_relocation_ptr + img_base_relocation_ptr->SizeOfBlock);
	}
}

const uint8_t *pe_load_file(
	const wchar_t * filepath
) {
	NTSTATUS					status;
	UNICODE_STRING				file_path;
	HANDLE						handle;
	OBJECT_ATTRIBUTES			obj_attrs;
	IO_STATUS_BLOCK				io_status_block;
	LARGE_INTEGER				file_offset;
	ULONG						index;
	ULONG						section_va, section_size;
	IMAGE_DOS_HEADER			img_dos_header;
	IMAGE_NT_HEADERS			img_nt_header;
	PIMAGE_SECTION_HEADER		img_section_header_ptr;
	PVOID						module;

	InitializeObjectAttributes(&obj_attrs, &file_path, OBJ_CASE_INSENSITIVE, NULL, NULL);
	RtlInitUnicodeString(&file_path, filepath);

	status = ZwCreateFile(&handle, FILE_ALL_ACCESS, &obj_attrs, &io_status_block, 0, 
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

	if (!NT_SUCCESS(status)) {
		return NULL;
	}

	file_offset.QuadPart = 0;
	status = ZwReadFile(handle, NULL, NULL, NULL, &io_status_block, &img_dos_header, sizeof(IMAGE_DOS_HEADER), &file_offset, NULL);
	if (!NT_SUCCESS(status)) {
		ZwClose(handle);
		return NULL;
	}

	file_offset.QuadPart = img_dos_header.e_lfanew;
	status = ZwReadFile(handle, NULL, NULL, NULL, &io_status_block, &img_nt_header, sizeof(IMAGE_NT_HEADERS), &file_offset, NULL);
	if (!NT_SUCCESS(status)) {
		ZwClose(handle);
		return NULL;
	}

	img_section_header_ptr = (PIMAGE_SECTION_HEADER)ExAllocatePoolWithTag(NonPagedPool, sizeof(IMAGE_SECTION_HEADER) * img_nt_header.FileHeader.NumberOfSections, 'epaw');
	if (img_section_header_ptr == NULL) {
		ZwClose(handle);
		return NULL;
	}

	file_offset.QuadPart += sizeof(IMAGE_NT_HEADERS);
	status = ZwReadFile(handle, NULL, NULL, NULL, &io_status_block, img_section_header_ptr, sizeof(IMAGE_SECTION_HEADER) * img_nt_header.FileHeader.NumberOfSections, &file_offset, NULL);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(img_section_header_ptr, 'epaw');
		ZwClose(handle);
		return NULL;
	}

	module = ExAllocatePoolWithTag(NonPagedPool, img_nt_header.OptionalHeader.SizeOfImage, 'epaw');
	if (module == NULL) {
		ExFreePoolWithTag(img_section_header_ptr, 'epaw');
		ZwClose(handle);
		return NULL;
	}
	memset(module, 0, img_nt_header.OptionalHeader.SizeOfImage);

	RtlCopyMemory(module, &img_dos_header, sizeof(IMAGE_DOS_HEADER));
	RtlCopyMemory(module, &img_nt_header, sizeof(IMAGE_NT_HEADERS));
	RtlCopyMemory(module, img_section_header_ptr, sizeof(IMAGE_SECTION_HEADER) * img_nt_header.FileHeader.NumberOfSections);

	for (index = 0; index < img_nt_header.FileHeader.NumberOfSections; index++) {
		section_va = img_section_header_ptr[index].VirtualAddress;
		section_size = max(img_section_header_ptr[index].Misc.VirtualSize, img_section_header_ptr[index].SizeOfRawData);
		file_offset.QuadPart = img_section_header_ptr[index].PointerToRawData;
		status = ZwReadFile(handle, NULL, NULL, NULL, &io_status_block, (PVOID)((uintptr_t)module + section_va), section_size, &file_offset, NULL);
		if (!NT_SUCCESS(status)) {
			ExFreePoolWithTag(img_section_header_ptr, 'epaw');
			ExFreePoolWithTag(module, 'epaw');
			ZwClose(handle);
			return NULL;
		}
	}
	ExFreePoolWithTag(img_section_header_ptr, 'epaw');
	ZwClose(handle);
	return module;
}