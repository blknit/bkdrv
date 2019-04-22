#include "utils.h"
#include "pe.h"

void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	DbgPrint("Driver Unload Success !");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegsiterPath)
{
    const uint8_t *new_module, *old_module;
    new_module = pe_load_file(L"\\??\\C:\\WINDOWS\\system32\\ntkrnlpa.exe");
    if (new_module == NULL) 
    {
        return STATUS_NOT_SUPPORTED;
    }
    old_module = get_module_base(pDriverObject, L"\\??\\C:\\WINDOWS\\system32\\ntkrnlpa.exe");
    if (old_module == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    fix_reloc_table(new_module, old_module);

    pDriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}