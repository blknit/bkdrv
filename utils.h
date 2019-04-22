#pragma once
#include <ntddk.h>
#include <ntimage.h>
KIRQL unset_wp();
VOID set_wp(KIRQL Irql);