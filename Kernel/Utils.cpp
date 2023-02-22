#include "main.h"

class Driver
{
public:
	UINT ProcessId;

	const bool Init(const BOOL PhysicalMode) {
		this->bPhysicalMode = PhysicalMode;
		this->hDriver = CreateFileA((E("\\\\.\\\svchost")), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (this->hDriver != INVALID_HANDLE_VALUE) {
			if (this->SharedBuffer = VirtualAlloc(0, sizeof(REQUEST_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
				UNICODE_STRING RegPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\fortnite2");
				if (!RegistryUtils::WriteRegistry(RegPath, RTL_CONSTANT_STRING(L"xxxxxxxx"), &this->SharedBuffer, REG_QWORD, 8)) {
					return false;
				}
				PVOID pid = (PVOID)GetCurrentProcessId();
				if (!RegistryUtils::WriteRegistry(RegPath, RTL_CONSTANT_STRING(L"xxxxxxxxx"), &pid, REG_QWORD, 8)) {
					return false;
				}
				auto OLD_MAGGICCODE = this->MAGGICCODE;
				SendRequest(99, 0);
				if (this->MAGGICCODE == OLD_MAGGICCODE)
					this->MAGGICCODE = (ULONG64)RegistryUtils::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"xxxxxxxxxx"));
				return true;
			}
		}
		return false;
	}
	
	

PMM_UNLOADED_DRIVER MmUnloadedDrivers;
PULONG MmLastUnloadedDriver;
ERESOURCE PsLoadedModuleResource;
UINT64 ntoskrnlBase = 0, ntoskrnlSize = 0;

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (UINT64)(dwAddress + i);

	return 0;
}

PVOID NTAPI GetKernelProcAddress(LPCWSTR SystemRoutineName)
{
	UNICODE_STRING Name;
	RtlInitUnicodeString(&Name, SystemRoutineName);
	return MmGetSystemRoutineAddress(&Name);
}

ULONG64 GeModuleBase(const char* Findmodule)
{
	ULONG modulesSize = 0;
	NTSTATUS ReturnCode = ZwQuerySystemInformation(SystemModuleInformation, 0, modulesSize, &modulesSize);

	if (!modulesSize)
		return 0;

	PRTL_PROCESS_MODULES ModuleList = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, modulesSize, 'ENON'); // 'ENON'

	ReturnCode = ZwQuerySystemInformation(SystemModuleInformation, ModuleList, modulesSize, &modulesSize);

	if (!NT_SUCCESS(ReturnCode))
		return 0;

	PRTL_PROCESS_MODULE_INFORMATION module = ModuleList->Modules;

	for (ULONG i = 0; i < ModuleList->NumberOfModules; i++)
	{
		if (strstr((char*)module[i].FullPathName, Findmodule))
		{
			if (ModuleList)
				ExFreePoolWithTag(ModuleList, 'ENON');

			return (UINT64)module[i].ImageBase;
		}
	}

	if (ModuleList)
		ExFreePoolWithTag(ModuleList, 'ENON');

	return 0;

}

PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

NTSTATUS PatternScan(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL) return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}
		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS ScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL);
	if (ppFound == NULL) return STATUS_INVALID_PARAMETER;

	PVOID base = (PVOID)ntoskrnlBase;
	if (!base) return STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr) return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = PatternScan(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) *(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);
			return status;
		}
	}
	return STATUS_NOT_FOUND;
}

BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
	UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\x0D\xCC\xCC\xCC\xCC\x33\xDB";
	UCHAR PiDTablePtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x3D\xCC\xCC\xCC\xCC\x0F\x83\xCC\xCC\xCC\xCC";

	PVOID PiDDBLockPtr = NULL;
	if (!NT_SUCCESS(ScanSection("PAGE", PiDDBLockPtr_sig, 0xCC, sizeof(PiDDBLockPtr_sig) - 1, (&PiDDBLockPtr)))) return FALSE;
	RtlZeroMemory(PiDDBLockPtr_sig, sizeof(PiDDBLockPtr_sig) - 1);

	PVOID PiDTablePtr = NULL;
	if (!NT_SUCCESS(ScanSection("PAGE", PiDTablePtr_sig, 0xCC, sizeof(PiDTablePtr_sig) - 1, (&PiDTablePtr)))) return FALSE;
	RtlZeroMemory(PiDTablePtr_sig, sizeof(PiDTablePtr_sig) - 1);


	UINT64 RealPtrPIDLock = NULL;
	RealPtrPIDLock = (UINT64)ntoskrnlBase +(UINT64)PiDDBLockPtr;
	*lock = (PERESOURCE)ResolveRelativeAddress((PVOID)RealPtrPIDLock, 3, 7);

	UINT64 RealPtrPIDTable = NULL;
	RealPtrPIDTable = (UINT64)(UINT64)ntoskrnlBase + (UINT64)PiDTablePtr;
	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress((PVOID)RealPtrPIDTable, 3, 7));

	return TRUE;
}

LONG ClearPiDDBCacheTable()
{
	PERESOURCE PiDDBLock = NULL;
	PRTL_AVL_TABLE PiDDBCacheTable = NULL;
	if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable) && PiDDBLock == NULL && PiDDBCacheTable == NULL) return 1;

	PIDCacheobj iqvw64e;
	iqvw64e.DriverName = RTL_CONSTANT_STRING(L"iqvw64e.sys");
	iqvw64e.TimeDateStamp = 0x5284F8FA;
	
	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
	
	PIDCacheobj* pFoundEntry = (PIDCacheobj*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &iqvw64e);
	if (pFoundEntry == NULL)
	{
		ExReleaseResourceLite(PiDDBLock);
		return 2;
	}
	else
	{
		RemoveEntryList(&pFoundEntry->List);
		RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);
		ExReleaseResourceLite(PiDDBLock);
		return 0;
	}
	return 3;
}

LONG RetrieveMmUnloadedDriversData(VOID)
{
	ULONG bytes = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (!bytes) return 1;
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);
	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
	if (!NT_SUCCESS(status)) return 2;
	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (!strcmp((char*)module[i].FullPathName, "\\SystemRoot\\system32\\ntoskrnl.exe"))
		{
			ntoskrnlBase = (UINT64)module[i].ImageBase;
			ntoskrnlSize = (UINT64)module[i].ImageSize;
			break;
		}
	}
	if (modules) ExFreePoolWithTag(modules, 0);

	UINT64 MmUnloadedDriversInstr = FindPattern((UINT64)ntoskrnlBase, (UINT64)ntoskrnlSize, (BYTE*)"\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");
	if (MmUnloadedDriversInstr == NULL) return 3;

	UINT64 MmLastUnloadedDriverInstr = FindPattern((UINT64)ntoskrnlBase, (UINT64)ntoskrnlSize, (BYTE*)"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32", "xx????xxx");
	if (MmLastUnloadedDriverInstr == NULL) return 4;

	MmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress((PVOID)MmUnloadedDriversInstr, 3, 7);
	MmLastUnloadedDriver = (PULONG)ResolveRelativeAddress((PVOID)MmLastUnloadedDriverInstr, 2, 6);

	return 0;
}

BOOLEAN IsUnloadedDriverEntryEmpty(_In_ PMM_UNLOADED_DRIVER Entry)
{
	if (Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL)
		return TRUE;
	else
		return FALSE;
}

BOOLEAN IsMmUnloadedDriversFilled(VOID)
{
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (IsUnloadedDriverEntryEmpty(Entry)) return FALSE;
	}
	return TRUE;
}

LONG ClearMmUnloadedDrivers(_In_ PUNICODE_STRING DriverName, _In_ BOOLEAN AccquireResource)
{
	if (AccquireResource) ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE);
	BOOLEAN Modified = FALSE;
	BOOLEAN Filled = IsMmUnloadedDriversFilled();
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (Modified)
		{
			PMM_UNLOADED_DRIVER PrevEntry = &MmUnloadedDrivers[Index - 1];
			RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));
			if (Index == MM_UNLOADED_DRIVERS_SIZE - 1) RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
		}
		else if (RtlEqualUnicodeString(DriverName, &Entry->Name, TRUE))
		{
			PVOID BufferPool = Entry->Name.Buffer;
			RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			ExFreePoolWithTag(BufferPool, 0x504D5448);
			*MmLastUnloadedDriver = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *MmLastUnloadedDriver) - 1;
			Modified = TRUE;
		}
	}
	if (Modified)
	{
		ULONG64 PreviousTime = 0;
		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index)
		{
			PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
			if (IsUnloadedDriverEntryEmpty(Entry)) continue;
			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) Entry->UnloadTime = PreviousTime - 48;
			PreviousTime = Entry->UnloadTime;
		}
		ClearMmUnloadedDrivers(DriverName, FALSE);
	}

	if (AccquireResource) ExReleaseResourceLite(&PsLoadedModuleResource);

	return Modified ? 0 : 1;
}
	
	NTSTATUS ReadProcessMemory(uint64_t src, void* dest, uint32_t size) {
		REQUEST_READ req;
		req.ProcessId = ProcessId;
		req.Src = src;
		req.Dest = dest;
		req.Size = size;
		req.bPhysicalMem = bPhysicalMode;
		return SendRequest(REQUEST_TYPE::READ, &req);
	}
	
	const UINT GetProcessId(const wchar_t* process_name) {
		UINT pid = 0;

		DWORD dwThreadCountMax = 0;

		// Create toolhelp snapshot.
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);
		// Walkthrough all processes.
		if (Process32First(snapshot, &process))
		{
			do
			{
				if (wcsstr(process.szExeFile, process_name))
				{
					DWORD dwTmpThreadCount = GetProcessThreadNumByID(process.th32ProcessID);
					if (dwTmpThreadCount > dwThreadCountMax)
					{
						dwThreadCountMax = dwTmpThreadCount;
						pid = process.th32ProcessID;
						break;
					}
				}
			} while (Process32Next(snapshot, &process));
		}
		CloseHandle(snapshot);
		return pid;
	}
	
	
std::wstring s2ws(const std::string& str) {
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

	std::wstring MBytesToWString(const char* lpcszString)
{
	int len = strlen(lpcszString);
	int unicodeLen = ::MultiByteToWideChar(CP_ACP, 0, lpcszString, -1, NULL, 0);
	wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
	memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
	::MultiByteToWideChar(CP_ACP, 0, lpcszString, -1, (LPWSTR)pUnicode, unicodeLen);
	std::wstring wString = (wchar_t*)pUnicode;
	delete[] pUnicode;
	return wString;
}

	
	
	std::string WStringToUTF8(const wchar_t* lpwcszWString)
{
	char* pElementText;
	int iTextLen = ::WideCharToMultiByte(CP_UTF8, 0, (LPWSTR)lpwcszWString, -1, NULL, 0, NULL, NULL);
	pElementText = new char[iTextLen + 1];
	memset((void*)pElementText, 0, (iTextLen + 1) * sizeof(char));
	::WideCharToMultiByte(CP_UTF8, 0, (LPWSTR)lpwcszWString, -1, pElementText, iTextLen, NULL, NULL);
	std::string strReturn(pElementText);
	delete[] pElementText;
	return strReturn;
}
	
	
