#include <ntddk.h>
#include "file.h"

typedef struct _AUX_ACCESS_DATA {
	PPRIVILEGE_SET PrivilegesUsed;
	GENERIC_MAPPING GenericMapping;
	ACCESS_MASK AccessesToAudit;
	ACCESS_MASK MaximumAuditMask;
	ULONG Unknown[256];
} AUX_ACCESS_DATA, *PAUX_ACCESS_DATA;

typedef struct _QUERY_DIRECTORY {
	ULONG Length;
	PUNICODE_STRING FileName;
	FILE_INFORMATION_CLASS FileInformationClass;
	ULONG FileIndex;
} QUERY_DIRECTORY, *PQUERY_DIRECTORY;

NTSTATUS ObCreateObject(KPROCESSOR_MODE ProbeMode, POBJECT_TYPE ObjectType, POBJECT_ATTRIBUTES ObjectAttributes, KPROCESSOR_MODE OwnershipMode, PVOID ParseContext, ULONG ObjectBodySize, ULONG PagedPoolCharge, ULONG NonPagedPoolCharge, PVOID *Object);
NTSTATUS SeCreateAccessState(PACCESS_STATE AccessState, PVOID AuxData, ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping);

NTSTATUS IoCompletionRoutine(
    IN PDEVICE_OBJECT device_object,
    IN PIRP irp,
    IN PVOID context
){
    *irp->UserIosb = irp->IoStatus;
    if(irp->UserEvent)
        KeSetEvent(irp->UserEvent, IO_NO_INCREMENT, 0);
    if(irp->MdlAddress){
        IoFreeMdl(irp->MdlAddress);
        irp->MdlAddress = NULL;
    }
    IoFreeIrp(irp);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS IrpCreateFile(
    IN PUNICODE_STRING FileName,
    IN ACCESS_MASK DesiredAccess,
    OUT PIO_STATUS_BLOCK io_status,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PDEVICE_OBJECT DeviceObject,
    IN PDEVICE_OBJECT RealDevice,
    OUT PVOID *Object
){
    NTSTATUS status;
    KEVENT event;
    PIRP irp;
    PIO_STACK_LOCATION irp_sp;
    IO_SECURITY_CONTEXT security_context;
    ACCESS_STATE access_state;
    OBJECT_ATTRIBUTES object_attributes;
    PFILE_OBJECT file_object;
    AUX_ACCESS_DATA aux_data;

    RtlZeroMemory(&aux_data, sizeof(AUX_ACCESS_DATA));
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);
    irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);

    if(irp == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    InitializeObjectAttributes(&object_attributes, NULL, OBJ_CASE_INSENSITIVE, 0, NULL);
    status = ObCreateObject(KernelMode,
                            *IoFileObjectType,
                            &object_attributes,
                            KernelMode,
                            NULL,
                            sizeof(FILE_OBJECT),
                            0,
                            0,
                            (PVOID *)&file_object);
    if(!NT_SUCCESS(status)){
        IoFreeIrp(irp);
        return status;
    }
    RtlZeroMemory(file_object, sizeof(FILE_OBJECT));
    file_object->Size = sizeof(FILE_OBJECT);
    file_object->Type = IO_TYPE_FILE;
    file_object->DeviceObject = RealDevice;

    if(CreateOptions & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)){
        file_object->Flags = FO_SYNCHRONOUS_IO;
        if(CreateOptions & FILE_SYNCHRONOUS_IO_ALERT)
            file_object->Flags |= FO_ALERTABLE_IO;
    }
    if(CreateOptions & FILE_NO_INTERMEDIATE_BUFFERING)
        file_object->Flags |= FO_NO_INTERMEDIATE_BUFFERING;

    file_object->FileName.MaximumLength = FileName->MaximumLength;
    file_object->FileName.Buffer = ExAllocatePool(NonPagedPool, FileName->MaximumLength);
    if (file_object->FileName.Buffer == NULL){
        IoFreeIrp(irp);
        ObDereferenceObject(file_object);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyUnicodeString(&file_object->FileName, FileName);
    KeInitializeEvent(&file_object->Lock, SynchronizationEvent, FALSE);
    KeInitializeEvent(&file_object->Event, NotificationEvent, FALSE);
    irp->MdlAddress = NULL;
    irp->Flags |= IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = io_status;
    irp->UserEvent = &event;
    irp->PendingReturned = FALSE;
    irp->Cancel = FALSE;
    irp->CancelRoutine = NULL;
    irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
    irp->Tail.Overlay.AuxiliaryBuffer = NULL;
    irp->Tail.Overlay.OriginalFileObject = file_object;
    status = SeCreateAccessState(&access_state,
                                 &aux_data,   
                                 DesiredAccess,   
                                 IoGetFileObjectGenericMapping());
    if(!NT_SUCCESS(status)){
        IoFreeIrp(irp);
        ExFreePool(file_object->FileName.Buffer);
        ObDereferenceObject(file_object);
        return status;
    }

    security_context.SecurityQos = NULL;
    security_context.AccessState = &access_state;
    security_context.DesiredAccess = DesiredAccess;
    security_context.FullCreateOptions = 0;

    irp_sp= IoGetNextIrpStackLocation(irp);
    irp_sp->MajorFunction = IRP_MJ_CREATE;
    irp_sp->DeviceObject = DeviceObject;
    irp_sp->FileObject =file_object;
    irp_sp->Parameters.Create.SecurityContext = &security_context;
    irp_sp->Parameters.Create.Options = (CreateDisposition << 24) | CreateOptions;
    irp_sp->Parameters.Create.FileAttributes = (USHORT)FileAttributes;
    irp_sp->Parameters.Create.ShareAccess = (USHORT)ShareAccess;
    irp_sp->Parameters.Create.EaLength = 0;

    IoSetCompletionRoutine(irp, IoCompletionRoutine, NULL, TRUE, TRUE, TRUE);
    status = IoCallDriver(DeviceObject, irp);

    if (status == STATUS_PENDING)
        KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);

    status = io_status->Status;
    if (!NT_SUCCESS(status)){
        ExFreePool(file_object->FileName.Buffer);
        file_object->FileName.Length = 0;
        file_object->DeviceObject = NULL;
        ObDereferenceObject(file_object);
    }else{
         InterlockedIncrement(&file_object->DeviceObject->ReferenceCount);
         if (file_object->Vpb)
              InterlockedIncrement(&file_object->Vpb->ReferenceCount);
         *Object = file_object;
    }
    return status;
}

NTSTATUS IrpCloseFile(
    IN PDEVICE_OBJECT DeviceObject,
    IN PFILE_OBJECT FileObject
){
    NTSTATUS status;
    KEVENT event;
    PIRP irp;
    PVPB vpb;
    IO_STATUS_BLOCK ioStatusBlock;
    PIO_STACK_LOCATION irpSp;

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);
    irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if (irp == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    irp->Tail.Overlay.OriginalFileObject = FileObject;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->RequestorMode = KernelMode;
    irp->UserEvent = &event;
    irp->UserIosb = &irp->IoStatus;
    irp->Overlay.AsynchronousParameters.UserApcRoutine = (PIO_APC_ROUTINE)NULL;
    irp->Flags = IRP_SYNCHRONOUS_API | IRP_CLOSE_OPERATION;
    irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->MajorFunction = IRP_MJ_CLEANUP;
    irpSp->FileObject = FileObject;
    status = IoCallDriver(DeviceObject, irp);
    if (status == STATUS_PENDING)
        KeWaitForSingleObject(&event,UserRequest,KernelMode,FALSE,NULL);
    IoReuseIrp(irp , STATUS_SUCCESS);
    KeClearEvent(&event);
    irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->MajorFunction = IRP_MJ_CLOSE;
    irpSp->FileObject = FileObject;
    irp->UserIosb = &ioStatusBlock;
    irp->UserEvent = &event;
    irp->Tail.Overlay.OriginalFileObject = FileObject;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->AssociatedIrp.SystemBuffer = (PVOID)NULL;
    irp->Flags = IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API;
    vpb = FileObject->Vpb;
    if (vpb && !(FileObject->Flags & FO_DIRECT_DEVICE_OPEN)){
        InterlockedDecrement(&vpb->ReferenceCount);
        FileObject->Flags |= FO_FILE_OPEN_CANCELLED;
    }
    status = IoCallDriver(DeviceObject, irp);
    if (status == STATUS_PENDING)
        KeWaitForSingleObject(&event,UserRequest,KernelMode,FALSE,NULL);
    IoFreeIrp(irp);
    return status;
}

NTSTATUS IrpReadFile(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN ULONG Length,
    OUT PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatusBlock
){
    NTSTATUS status;
    KEVENT event;
    PIRP irp;
    PIO_STACK_LOCATION irpSp;
    PDEVICE_OBJECT deviceObject;
    if (ByteOffset == NULL){
        if (!(FileObject->Flags & FO_SYNCHRONOUS_IO))
            return STATUS_INVALID_PARAMETER;
        ByteOffset = &FileObject->CurrentByteOffset;
    }
    if (FileObject->Vpb == 0 || FileObject->Vpb->RealDevice == NULL)
        return STATUS_UNSUCCESSFUL;
    deviceObject = FileObject->Vpb->DeviceObject;
    irp = IoAllocateIrp(deviceObject->StackSize, FALSE);
    if (irp == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    irp->MdlAddress = IoAllocateMdl(Buffer, Length, FALSE, TRUE, NULL);
    if (irp->MdlAddress == NULL){
        IoFreeIrp(irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(irp->MdlAddress);
    irp->Flags = IRP_READ_OPERATION;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = IoStatusBlock;
    irp->UserEvent = &event;
    irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = FileObject;
    irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->MajorFunction = IRP_MJ_READ;
    irpSp->MinorFunction = IRP_MN_NORMAL;
    irpSp->DeviceObject = deviceObject;
    irpSp->FileObject = FileObject;
    irpSp->Parameters.Read.Length = Length;
    irpSp->Parameters.Read.ByteOffset = *ByteOffset;
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);   
    IoSetCompletionRoutine(irp, IoCompletionRoutine, NULL, TRUE, TRUE, TRUE);
    status = IoCallDriver(deviceObject, irp);
    if (status == STATUS_PENDING)
        status = KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);
    return status;
}

NTSTATUS IrpFileWrite(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN ULONG Length,
    IN PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatusBlock
){
    NTSTATUS status;
    KEVENT event;
    PIRP irp;
    PIO_STACK_LOCATION irpSp;
    PDEVICE_OBJECT deviceObject;

    if (ByteOffset == NULL)
    {   
        if (!(FileObject->Flags & FO_SYNCHRONOUS_IO))
            return STATUS_INVALID_PARAMETER;

        ByteOffset = &FileObject->CurrentByteOffset;
    }

    if (FileObject->Vpb == 0 || FileObject->Vpb->RealDevice == NULL)
        return STATUS_UNSUCCESSFUL;

    deviceObject = FileObject->Vpb->DeviceObject;
    irp = IoAllocateIrp(deviceObject->StackSize, FALSE);

    if (irp == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    irp->MdlAddress = IoAllocateMdl(Buffer, Length, FALSE, TRUE, NULL);

    if (irp->MdlAddress == NULL)
    {
        IoFreeIrp(irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool(irp->MdlAddress);

    irp->Flags = IRP_WRITE_OPERATION;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = IoStatusBlock;
    irp->UserEvent = &event;
    irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = FileObject;

    irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->MajorFunction = IRP_MJ_WRITE;
    irpSp->MinorFunction = IRP_MN_NORMAL;
    irpSp->DeviceObject = deviceObject;
    irpSp->FileObject = FileObject;
    irpSp->Parameters.Write.Length = Length;
    irpSp->Parameters.Write.ByteOffset = *ByteOffset;

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);
    IoSetCompletionRoutine(irp, IoCompletionRoutine, NULL, TRUE, TRUE, TRUE);
    status = IoCallDriver(deviceObject, irp);

    if (status == STATUS_PENDING)
        status = KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);

    return status;
}   
  
NTSTATUS IrpFileQuery(
    IN PFILE_OBJECT FileObject,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
){
        NTSTATUS status;
        KEVENT event;
        PIRP irp;
        IO_STATUS_BLOCK ioStatus;
        PIO_STACK_LOCATION irpSp;
        PDEVICE_OBJECT deviceObject;
  
        if (FileObject->Vpb == 0 || FileObject->Vpb->RealDevice == NULL)
                return STATUS_UNSUCCESSFUL;
  
        deviceObject = FileObject->Vpb->DeviceObject;
        KeInitializeEvent(&event, SynchronizationEvent, FALSE);
        irp = IoAllocateIrp(deviceObject->StackSize, FALSE);
  
        if (irp == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
  
        irp->Flags = IRP_BUFFERED_IO;
        irp->AssociatedIrp.SystemBuffer = FileInformation;
        irp->RequestorMode = KernelMode;
        irp->Overlay.AsynchronousParameters.UserApcRoutine = (PIO_APC_ROUTINE)NULL;
        irp->UserEvent = &event;
        irp->UserIosb = &ioStatus;
        irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
        irp->Tail.Overlay.OriginalFileObject = FileObject;
  
        irpSp = IoGetNextIrpStackLocation(irp);
        irpSp->MajorFunction = IRP_MJ_QUERY_INFORMATION;
        irpSp->DeviceObject = deviceObject;
        irpSp->FileObject = FileObject;
        irpSp->Parameters.QueryFile.Length = Length;
        irpSp->Parameters.QueryFile.FileInformationClass = FileInformationClass;
  
        IoSetCompletionRoutine(irp, IoCompletionRoutine, NULL, TRUE, TRUE, TRUE);
        status = IoCallDriver(deviceObject, irp);
  
        if (status == STATUS_PENDING)
                KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);
  
        return ioStatus.Status;
}   
  
NTSTATUS IrpDirectoryQuery(
    IN PFILE_OBJECT FileObject,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    OUT PVOID Buffer,
    IN ULONG Length 
){
    NTSTATUS status;
    KEVENT event;
    PIRP irp;
    IO_STATUS_BLOCK ioStatus;
    PIO_STACK_LOCATION irpSp;
    PDEVICE_OBJECT deviceObject;
    PQUERY_DIRECTORY queryDirectory;
    
    if (FileObject->Vpb == 0 || FileObject->Vpb->RealDevice == NULL)
        return STATUS_UNSUCCESSFUL;
    
    deviceObject = FileObject->Vpb->DeviceObject;
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);
    irp = IoAllocateIrp(deviceObject->StackSize, FALSE);
    
    if (irp == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    
    irp->Flags = IRP_INPUT_OPERATION | IRP_BUFFERED_IO;
    irp->RequestorMode = KernelMode;
    irp->UserEvent = &event;
    irp->UserIosb = &ioStatus;
    irp->UserBuffer = Buffer;
    irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = FileObject;
    irp->Overlay.AsynchronousParameters.UserApcRoutine = (PIO_APC_ROUTINE)NULL;
    //irp->Pointer = FileObject;
    
    irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
    irpSp->MinorFunction = IRP_MN_QUERY_DIRECTORY;
    irpSp->DeviceObject = deviceObject;
    irpSp->FileObject = FileObject;
    
    queryDirectory = (PQUERY_DIRECTORY)&irpSp->Parameters;
    queryDirectory->Length = Length;
    queryDirectory->FileName = NULL;
    queryDirectory->FileInformationClass = FileInformationClass;
    queryDirectory->FileIndex = 0;
    
    IoSetCompletionRoutine(irp, IoCompletionRoutine, NULL, TRUE, TRUE, TRUE);
    status = IoCallDriver(deviceObject, irp);
    
    if (status == STATUS_PENDING)
    {   
        KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, NULL);
        status = ioStatus.Status;
    }
    
    return status;
}

NTSTATUS

IrpSetInformationFile(
    IN PFILE_OBJECT  FileObject,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN PVOID  FileInformation,
    IN ULONG  Length,
    IN FILE_INFORMATION_CLASS  FileInformationClass,
    IN BOOLEAN  ReplaceIfExists)
{
    NTSTATUS ntStatus;
    PIRP Irp;
    KEVENT kEvent;
    PIO_STACK_LOCATION IrpSp;

    if (FileObject->Vpb == 0 || FileObject->Vpb->DeviceObject == NULL)
        return STATUS_UNSUCCESSFUL;

    Irp = IoAllocateIrp(FileObject->Vpb->DeviceObject->StackSize, FALSE);
    if(Irp == NULL) 
        return STATUS_INSUFFICIENT_RESOURCES;

    KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

    Irp->AssociatedIrp.SystemBuffer = FileInformation;
    Irp->UserEvent = &kEvent;
    Irp->UserIosb = IoStatusBlock;
    Irp->RequestorMode = KernelMode;
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    Irp->Tail.Overlay.OriginalFileObject = FileObject;

    IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
    IrpSp->DeviceObject = FileObject->Vpb->DeviceObject;
    IrpSp->FileObject = FileObject;
    IrpSp->Parameters.SetFile.ReplaceIfExists = ReplaceIfExists;
    IrpSp->Parameters.SetFile.FileObject = FileObject;
    IrpSp->Parameters.SetFile.AdvanceOnly = FALSE;
    IrpSp->Parameters.SetFile.Length = Length;
    IrpSp->Parameters.SetFile.FileInformationClass = FileInformationClass;

    IoSetCompletionRoutine(Irp, IoCompletionRoutine, 0, TRUE, TRUE, TRUE);
    ntStatus = IoCallDriver(FileObject->Vpb->DeviceObject, Irp);
    if (ntStatus == STATUS_PENDING)
        KeWaitForSingleObject(&kEvent, Executive, KernelMode, TRUE, 0);

    return IoStatusBlock->Status;
}
  
BOOLEAN GetDriveObject(
    IN ULONG DriveNumber,
    OUT PDEVICE_OBJECT *DeviceObject,
    OUT PDEVICE_OBJECT *ReadDevice
){
    WCHAR driveName[] = L"//DosDevices//A://";
    UNICODE_STRING deviceName;
    HANDLE deviceHandle;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    PFILE_OBJECT fileObject;
    NTSTATUS status;
    
    if (DriveNumber >= 'A' && DriveNumber <= 'Z')
    {
        driveName[12] = (CHAR)DriveNumber;
    }
    else if (DriveNumber >= 'a' && DriveNumber <= 'z')
    {
        driveName[12] = (CHAR)DriveNumber - 'a' + 'A';
    }
    else
    {
        return FALSE;
    }
    
    RtlInitUnicodeString(&deviceName, driveName);
    
    InitializeObjectAttributes(&objectAttributes,
                                &deviceName,
                                OBJ_CASE_INSENSITIVE,
                                NULL,
                                NULL);

    status = IoCreateFile(&deviceHandle,
                            SYNCHRONIZE | FILE_ANY_ACCESS,
                            &objectAttributes,
                            &ioStatus,
                            NULL,
                            0,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_OPEN,
                            FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
                            NULL,
                            0,
                            CreateFileTypeNone,
                            NULL,
                            0x100);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Could not open drive %c: %x/n", DriveNumber, status);
        return FALSE;
    }
    
    status = ObReferenceObjectByHandle(deviceHandle,
                                        FILE_READ_DATA,
                                        *IoFileObjectType,
                                        KernelMode,
                                        &fileObject,
                                        NULL);

    if (!NT_SUCCESS(status))   
    {
        DbgPrint("Could not get fileobject from handle: %c/n", DriveNumber);
        ZwClose(deviceHandle);
        return FALSE;
    }   
    
    if (fileObject->Vpb == 0 || fileObject->Vpb->RealDevice == NULL)
    {
        ObDereferenceObject(fileObject);
        ZwClose(deviceHandle);
        return FALSE;
    }
    
    *DeviceObject = fileObject->Vpb->DeviceObject;
    *ReadDevice = fileObject->Vpb->RealDevice;
    
    ObDereferenceObject(fileObject);
    ZwClose(deviceHandle);
    
    return TRUE;   
}  

NTSTATUS ForceDeleteFile(UNICODE_STRING ustrFileName)
{
    NTSTATUS status = STATUS_SUCCESS;
    PFILE_OBJECT pFileObject = NULL;
    IO_STATUS_BLOCK iosb = { 0 };
    FILE_BASIC_INFORMATION fileBaseInfo = { 0 };
    FILE_DISPOSITION_INFORMATION fileDispositionInfo = { 0 };
    PVOID pImageSectionObject = NULL;
    PVOID pDataSectionObject = NULL;
    PVOID pSharedCacheMap = NULL;

    status = IrpCreateFile(&ustrFileName, GENERIC_READ | GENERIC_WRITE,
        &iosb, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, &pFileObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("IrpCreateFile Error[0x%X]\n", status);
        return FALSE;
    }

    RtlZeroMemory(&fileBaseInfo, sizeof(fileBaseInfo));
    fileBaseInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    status = IrpSetInformationFile(pFileObject, &iosb, &fileBaseInfo, sizeof(fileBaseInfo), FileBasicInformation, FALSE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("IrpSetInformationFile[SetInformation] Error[0x%X]\n", status);
        return status;
    }

    if (pFileObject->SectionObjectPointer)
    {

        pImageSectionObject = pFileObject->SectionObjectPointer->ImageSectionObject;
        pDataSectionObject = pFileObject->SectionObjectPointer->DataSectionObject;
        pSharedCacheMap = pFileObject->SectionObjectPointer->SharedCacheMap;

        pFileObject->SectionObjectPointer->ImageSectionObject = NULL;
        pFileObject->SectionObjectPointer->DataSectionObject = NULL;
        pFileObject->SectionObjectPointer->SharedCacheMap = NULL;
    }

    RtlZeroMemory(&fileDispositionInfo, sizeof(fileDispositionInfo));
    fileDispositionInfo.DeleteFile = TRUE;
    status = IrpSetInformationFile(pFileObject, &iosb, &fileDispositionInfo, sizeof(fileDispositionInfo), FileDispositionInformation, FALSE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("IrpSetInformationFile[DeleteFile] Error[0x%X]\n", status);
        return status;
    }

    if (pFileObject->SectionObjectPointer)
    {
        pFileObject->SectionObjectPointer->ImageSectionObject = pImageSectionObject;
        pFileObject->SectionObjectPointer->DataSectionObject = pDataSectionObject;
        pFileObject->SectionObjectPointer->SharedCacheMap = pSharedCacheMap;
    }

    ObDereferenceObject(pFileObject);

    return status;
}