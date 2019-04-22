#include <ntifs.h>
#include <wdm.h>
#include "utils.h"
KIRQL unset_wp()
{
	KIRQL Irql = KeRaiseIrqlToDpcLevel();
	UINT_PTR cr0 = __readcr0();

	cr0 &= ~0x10000;
	__writecr0(cr0);
	_disable();

	return Irql;
}

VOID set_wp(KIRQL Irql)
{
	UINT_PTR cr0 = __readcr0();

	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);

	KeLowerIrql(Irql);
}