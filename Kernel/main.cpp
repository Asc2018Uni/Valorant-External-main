#include "main.h"

void retreiveData() {
	while (true) {
		uintptr_t world = decryptWorld(g_base_address);

		uintptr_t game_instance = read<uintptr_t>(world + offsets::game_instance);
		uintptr_t persistent_level = read<uintptr_t>(world + offsets::persistent_level);

		uintptr_t local_player_array = read<uintptr_t>(game_instance + offsets::local_player_array);
		uintptr_t local_player = read<uintptr_t>(local_player_array);
		uintptr_t local_player_controller = read<uintptr_t>(local_player + offsets::local_player_controller);
		local_player_pawn = read<uintptr_t>(local_player_controller + offsets::local_player_pawn);
		uintptr_t local_damage_handler = read<uintptr_t>(local_player_pawn + offsets::damage_handler);
		uintptr_t local_player_state = read<uintptr_t>(local_player_pawn + offsets::player_state);
		uintptr_t local_team_component = read<uintptr_t>(local_player_state + offsets::team_component);
		int local_team_id = read<int>(local_team_component + offsets::team_id);

		uintptr_t camera_manager = read<uintptr_t>(local_player_controller + offsets::camera_manager);

		uintptr_t actor_array = read<uintptr_t>(persistent_level + offsets::actor_array);
		int actor_count = read<int>(persistent_level + offsets::actor_count);

		g_local_player_controller = local_player_controller;
		g_local_player_pawn = local_player_pawn;
		g_local_damage_handler = local_damage_handler;
		g_camera_manager = camera_manager;
		g_local_team_id = local_team_id;

		enemy_collection = retreiveValidEnemies(actor_array, actor_count);
		Sleep(2500);
	}
}


PDRIVER_DISPATCH ACPIOriginalDispatch = 0;





NTSTATUS ProcessReadWriteMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes = 0;

	if (NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, UserMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}


NTSTATUS CustomDispatch(PDEVICE_OBJECT device, PIRP irp)
{
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS Status;
	ULONG BytesIO = 0;

	//Here you can do your custom calls

	if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_DISK_GET_DRIVE_GEOMETRY)
	{
		CUSTOM_IOCTL_CALL* Buffer = (CUSTOM_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;

		if (Buffer->Filter == 0xDEADBEEFCAFEBEEF)
		{
			if (Buffer->ControlCode == READ_PROCESS_MEMORY_IOCTL)
			{
				READ_PROCESS_MEMORY* UserlandBuffer = (READ_PROCESS_MEMORY*)irp->AssociatedIrp.SystemBuffer;

				PEPROCESS TargetProcess = 0;

				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)UserlandBuffer->ProcessId, &TargetProcess))) {

					Status = ProcessReadWriteMemory(TargetProcess, (PVOID)UserlandBuffer->ProcessAddress, IoGetCurrentProcess(), (PVOID)UserlandBuffer->OutBuffer, UserlandBuffer->Length);
					ObfDereferenceObject(TargetProcess);
				}
				Status = STATUS_SUCCESS;
				BytesIO = sizeof(READ_PROCESS_MEMORY);
			}
			else if (Buffer->ControlCode == WRITE_PROCESS_MEMORY_IOCTL)
			{
				WRITE_PROCESS_MEMORY* UserlandBuffer = (WRITE_PROCESS_MEMORY*)irp->AssociatedIrp.SystemBuffer;

				PEPROCESS TargetProcess = 0;

				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)UserlandBuffer->ProcessId, &TargetProcess))) {
					Status = ProcessReadWriteMemory(IoGetCurrentProcess(), (PVOID)UserlandBuffer->InBuffer, TargetProcess, (PVOID)UserlandBuffer->ProcessAddress, UserlandBuffer->Length);

					ObfDereferenceObject(TargetProcess);
				}
				Status = STATUS_SUCCESS;
				BytesIO = sizeof(WRITE_PROCESS_MEMORY);
			}
			else if (Buffer->ControlCode == GET_PROCESS_BASE_IOCTL)
			{
				GET_PROCESS_BASE* UserlandBuffer = (GET_PROCESS_BASE*)irp->AssociatedIrp.SystemBuffer;

				PEPROCESS TargetProcess = 0;

				UserlandBuffer->ProcessBaseAddres = -1;

				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)UserlandBuffer->ProcessId, &TargetProcess))) {
					UserlandBuffer->ProcessBaseAddres = (unsigned __int64)PsGetProcessSectionBaseAddress(TargetProcess);

					ObfDereferenceObject(TargetProcess);
				}
				Status = STATUS_SUCCESS;
				BytesIO = sizeof(GET_PROCESS_BASE);
			}
			else if (Buffer->ControlCode == GET_PROCESS_PEB_IOCTL)
			{
				GET_PROCESS_PEB* UserlandBuffer = (GET_PROCESS_PEB*)irp->AssociatedIrp.SystemBuffer;

				PEPROCESS TargetProcess = 0;

				UserlandBuffer->ProcessBaseAddres = -1;

				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)UserlandBuffer->ProcessId, &TargetProcess))) {
					UserlandBuffer->ProcessBaseAddres = (unsigned __int64)PsGetProcessPeb(TargetProcess);

					ObfDereferenceObject(TargetProcess);
				}
				Status = STATUS_SUCCESS;
				BytesIO = sizeof(GET_PROCESS_PEB);
			}

			irp->IoStatus.Status = Status;
			irp->IoStatus.Information = BytesIO;

			IofCompleteRequest(irp, IO_NO_INCREMENT);
			return Status;
		}
	}

	return ACPIOriginalDispatch(device, irp);
}

NTSTATUS DriverEntry(PVOID lpBaseAddress, DWORD32 dwSize)
{
	RetrieveMmUnloadedDriversData();
	ClearPiDDBCacheTable();

	UNICODE_STRING iqvw64e = RTL_CONSTANT_STRING(L"iqvw64e.sys");
	ClearMmUnloadedDrivers(&iqvw64e, true);

	PDRIVER_OBJECT ACPIDriverObject = nullptr;

	UNICODE_STRING DriverObjectName = RTL_CONSTANT_STRING(L"\\Driver\\ACPI");
	ObReferenceObjectByName(&DriverObjectName, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&ACPIDriverObject);

	if (ACPIDriverObject)
	{
		ACPIOriginalDispatch = ACPIDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

		ULONG64 DispatchHookAddr = (ULONG64)DispatchHook;

		*(ULONG64*)(DispatchHookAddr + 0x6) = (ULONG64)CustomDispatch;

		ULONG64 TraceMessageHookInst = FindPattern((UINT64)ACPIDriverObject->DriverStart, ACPIDriverObject->DriverSize, (BYTE*)"\xB8\x0C\x00\x00\x00\x44\x0F\xB7\xC8\x8D\x50\x00", "xxxxxxxxxxx?");

		if (TraceMessageHookInst)
		{
			TraceMessageHookInst += 0xC;

			ULONG64 pfnWppTraceMessagePtr = (ULONG64)ResolveRelativeAddress((PVOID)TraceMessageHookInst, 3, 7);

			if (pfnWppTraceMessagePtr)
			{
				*(ULONG64*)(pfnWppTraceMessagePtr) = DispatchHookAddr;

				ACPIDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)TraceMessageHookInst;

				Printf("ACAPI IRP_MJ_DEVICE_CONTROL Hooked!\n");
			}
		}
	}
	return STATUS_SUCCESS;
}

	void initialize()
	{
		using namespace d3d9;
		if (AllocConsole()) {
			freopen("CONIN$", "r", stdin);
			freopen("CONOUT$", "w", stdout);
			freopen("CONOUT$", "w", stderr);
		}

		std::string proc_name = "GTA5.exe";
		game_window = FindWindow(0, "Grand Theft Auto V");

		if (c_mem::get()->initialize(game_window)) {
			printf("GTA5.exe ProcessID -> %i\n\n", int(g::pid));
		} 
		else {
			game_window = FindWindow("grcWindow", 0);
			if (!c_mem::get()->initialize(game_window)) {
				printf(("GTA5 is not running... exiting\n"));
				std::this_thread::sleep_for(std::chrono::seconds(3));
				exit(0);
			} 
			else {
				proc_name = "FiveM_GTAProcess.exe";
			}
		}

		

static Driver* driver = new Driver;

template <typename T>
T read(const uintptr_t address)
{
	T buffer{ };
	driver->ReadProcessMemory(address, &buffer, sizeof(T));
	return buffer;
}
template <typename T>
T write(const uintptr_t address, T buffer)
{
	driver->WriteProcessMemory((PVOID)&buffer, (PVOID)address, sizeof(T));
	return buffer;
}
std::string readwtf(uintptr_t Address, void* Buffer, SIZE_T Size)
{
	driver->ReadProcessMemory(Address, Buffer, Size);

	char name[255] = { 0 };
	memcpy(&name, Buffer, Size);

	return std::string(name);
}
		
		namespace jm {

    namespace detail {

        template<std::size_t Size>
        XORSTR_FORCEINLINE constexpr std::size_t _buffer_size()
        {
            return ((Size / 16) + (Size % 16 != 0)) * 2;
        }

        template<std::uint32_t Seed>
        XORSTR_FORCEINLINE constexpr std::uint32_t key4() noexcept
        {
            std::uint32_t value = Seed;
            for (char c : __TIME__)
                value = static_cast<std::uint32_t>((value ^ c) * 16777619ull);
            return value;
        }

        template<std::size_t S>
        XORSTR_FORCEINLINE constexpr std::uint64_t key8()
        {
            constexpr auto first_part = key4<2166136261 + S>();
            constexpr auto second_part = key4<first_part>();
            return (static_cast<std::uint64_t>(first_part) << 32) | second_part;
        }

        // loads up to 8 characters of string into uint64 and xors it with the key
        template<std::size_t N, class CharT>
        XORSTR_FORCEINLINE constexpr std::uint64_t
            load_xored_str8(std::uint64_t key, std::size_t idx, const CharT* str) noexcept
        {
            using cast_type = typename std::make_unsigned<CharT>::type;
            constexpr auto value_size = sizeof(CharT);
            constexpr auto idx_offset = 8 / value_size;

            std::uint64_t value = key;
            for (std::size_t i = 0; i < idx_offset && i + idx * idx_offset < N; ++i)
                value ^=
                (std::uint64_t{ static_cast<cast_type>(str[i + idx * idx_offset]) }
            << ((i % idx_offset) * 8 * value_size));

            return value;
        }
