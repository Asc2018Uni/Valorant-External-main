std:: namespace ("DriverController")



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
				return true;
			}
		}
		return false;
	}




unsigned __int32 DriverController::GetProcessPidByName(const wchar_t* ProcessName)
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) {
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap);
	return 0;
}

bool DriverController::ResetProcessId(const wchar_t* TargetProcessName)
{
	TargetProcessPid = GetProcessPidByName(TargetProcessName);

	if (!TargetProcessPid)
		return false;

	return true;
}

DriverController::DriverController(unsigned int TargetProcessPid)
{
	DriverHandle = INVALID_HANDLE_VALUE;

	this->TargetProcessPid = TargetProcessPid;

	if (!this->TargetProcessPid) {

		printf("Target Process Does not Exist... did you mean to do this?\n");
	}

	DriverHandle = CreateFile(TEXT("\\\\.\\\ACPI_ROOT_OBJECT"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

DriverController::DriverController(const wchar_t* TargetProcessName)
{
	DriverHandle = INVALID_HANDLE_VALUE;

	TargetProcessPid = GetProcessPidByName(TargetProcessName);

	if (!TargetProcessPid) {

		printf("Target Process Does not Exist... did you mean to do this?\n");
	}

	DriverHandle = CreateFile(TEXT("\\\\.\\\ACPI_ROOT_OBJECT"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

DriverController::~DriverController()
{
	if (DriverHandle != INVALID_HANDLE_VALUE)
		CloseHandle(DriverHandle);
}

bool DriverController::WriteProcessMemory(unsigned __int64 Address, void* Buffer, unsigned __int32 Length)
{
	if (!Address || !Buffer || !Length)
		return false;

	unsigned char* TempAllocationBuffer = (unsigned char*)malloc(Length);

	WRITE_PROCESS_MEMORY DriverCall;

	DriverCall.Filter = 0xDEADBEEFCAFEBEEF;
	DriverCall.ControlCode = WRITE_PROCESS_MEMORY_IOCTL;

	DriverCall.ProcessAddress = Address;
	DriverCall.InBuffer = (unsigned __int64)TempAllocationBuffer;
	DriverCall.Length = Length;
	DriverCall.ProcessId = TargetProcessPid;

	memcpy(TempAllocationBuffer, Buffer, Length);

	DWORD BytesOut = 0;

	if (DeviceIoControl(DriverHandle, IOCTL_DISK_GET_DRIVE_GEOMETRY, &DriverCall, sizeof(DriverCall), &DriverCall, sizeof(DriverCall), &BytesOut, 0)) {

		free(TempAllocationBuffer);
		return true;
	}

	free(TempAllocationBuffer);
	return false;
}

bool DriverController::ReadProcessMemory(unsigned __int64 Address, void* Buffer, unsigned __int32 Length)
{
	if (!Address || !Buffer || !Length)
		return false;

	unsigned char* TempAllocationBuffer = (unsigned char*)malloc(Length);

	READ_PROCESS_MEMORY DriverCall;
	DriverCall.Filter = 0xDEADBEEFCAFEBEEF;
	DriverCall.ControlCode = READ_PROCESS_MEMORY_IOCTL;

	DriverCall.ProcessAddress = Address;
	DriverCall.OutBuffer = (unsigned __int64)TempAllocationBuffer;
	DriverCall.Length = Length;
	DriverCall.ProcessId = TargetProcessPid;

	DWORD BytesOut = 0;

	if (DeviceIoControl(DriverHandle, IOCTL_DISK_GET_DRIVE_GEOMETRY, &DriverCall, sizeof(DriverCall), &DriverCall, sizeof(DriverCall), &BytesOut, 0)) {

		memcpy(Buffer, TempAllocationBuffer, Length);

		free(TempAllocationBuffer);
		return true;
	}

	free(TempAllocationBuffer);
	return false;
}



unsigned long long DriverController::ReadUInt64(unsigned long long Address)
{
	unsigned long long buffer = 0;

	this->ReadProcessMemory((unsigned long long)Address, (void*)&buffer, 8);

	return (buffer);
}

unsigned short DriverController::ReadUInt16(unsigned long long Address)
{
	unsigned short buffer = 0;

	this->ReadProcessMemory((unsigned long long)Address, (void*)&buffer, 2);

	return (buffer);
}

unsigned int  DriverController::ReadUInt32(unsigned long long Address)
{
	unsigned int  buffer = 0;

	this->ReadProcessMemory((unsigned long long)Address, (void*)&buffer, 4);

	return (buffer);
}

float DriverController::ReadFloat(unsigned long long Address)
{
	float buffer = 0;

	this->ReadProcessMemory((unsigned long long)Address, (void*)&buffer, 4);

	return (buffer);
}

NTSTATUS ProcessReadWriteMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes = 0;

	if (NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, UserMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

void DriverController::WriteByte(unsigned long long Address, unsigned char data)
{
	this->WriteProcessMemory((unsigned long long)Address, (void*)&data, 1);
}

void DriverController::WriteUInt32(unsigned long long Address, unsigned int data)
{
	this->WriteProcessMemory((unsigned long long)Address, (void*)&data, 4);
}

	this->WriteProcessMemory((unsigned long long)Address, (void*)&data, 8);
}

		if (game_window) {
			RECT client;
			GetClientRect(game_window, &client);
			GetWindowRect(game_window, &window_rect);
			screen_width = window_rect.right - window_rect.left;
			screen_height = window_rect.bottom - window_rect.top;
			overlay_hwnd = CreateWindowEx(NULL,
				window_name,
				window_name,
				WS_POPUP | WS_VISIBLE,
				window_rect.left, window_rect.top, screen_width, screen_height,
				NULL,
				NULL,
				NULL,
				NULL);

			MARGINS margins = { -1 };
			DwmExtendFrameIntoClientArea(overlay_hwnd, &margins);
			SetWindowLong(overlay_hwnd, GWL_EXSTYLE, WS_EX_LAYERED | WS_EX_TRANSPARENT);
		}

		directx_init(overlay_hwnd);
		MSG msg;
		while (true) {
			while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
			if (msg.message == WM_QUIT)
				exit(0);

			std::this_thread::sleep_for(std::chrono::milliseconds(120));
		}
	}
}

int PIDManager::GetProcessIdByName(LPCTSTR szProcess)//ע��Ҫ��exe��׺
{
	int dwRet = -1;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe32);
	do
	{
		if (_tcsicmp(pe32.szExeFile, szProcess) == 0)
		{
			dwRet = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe32));
	CloseHandle(hSnapshot);
	return dwRet;
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

        // forces compiler to use registers instead of stuffing constants in rdata
        XORSTR_FORCEINLINE std::uint64_t load_from_reg(std::uint64_t value) noexcept
        {
#if defined(__clang__) || defined(__GNUC__)
            asm("" : "=r"(value) : "0"(value) : );
            return value;
#else
            volatile std::uint64_t reg = value;
            return reg;
#endif
        }

    } // namespace detail

    template<class CharT, std::size_t Size, class Keys, class Indices>
    class xor_string;

    template<class CharT, std::size_t Size, std::uint64_t... Keys, std::size_t... Indices>
    class xor_string<CharT, Size, std::integer_sequence<std::uint64_t, Keys...>, std::index_sequence<Indices...>> {
#ifndef JM_XORSTR_DISABLE_AVX_INTRINSICS
        constexpr static inline std::uint64_t alignment = ((Size > 16) ? 32 : 16);
#else
        constexpr static inline std::uint64_t alignment = 16;
#endif



static void glfwErrorCallback(int error, const char* description)
{
	
}


	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO(); (void)io;

	ImGui::StyleColorsLight();

	// Setup Platform/Renderer backends
	ImGui_ImplGlfw_InitForOpenGL(g_window, true);
	ImGui_ImplOpenGL3_Init(E("#version 130"));

	ImFont* font = io.Fonts->AddFontFromFileTTF(E("Roboto-Light.ttf"), 18.0f, NULL, io.Fonts->GetGlyphRangesJapanese());
	IM_ASSERT(font != NULL);
}


void cleanupWindow() {
	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	glfwDestroyWindow(g_window);
	glfwTerminate();
}

BOOL CALLBACK retreiveValorantWindow(HWND hwnd, LPARAM lparam) {
	DWORD process_id;
	GetWindowThreadProcessId(hwnd, &process_id);
	if (process_id == profetrol) {
		valorant_window = hwnd;
	}
	return TRUE;
}

void activateValorantWindow() {
	SetForegroundWindow(valorant_window);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
}

void handleKeyPresses() {
	// Toggle overlay
	if (GetAsyncKeyState(VK_INSERT) & 1) {
		g_overlay_visible = !g_overlay_visible;
		glfwSetWindowAttrib(g_window, GLFW_MOUSE_PASSTHROUGH, !g_overlay_visible);
		if (g_overlay_visible) {
			HWND overlay_window = glfwGetWin32Window(g_window);
			SetForegroundWindow(overlay_window);
		}
		else {
			activateValorantWindow();
		}
	}
}

uintptr_t decryptWorld(uintptr_t base_address) {
	const auto key = read<uintptr_t>(base_address + offsets::uworld_key);
	const auto state = read<State>(base_address + offsets::uworld_state);
	const auto uworld_ptr = decrypt_uworld(key, (uintptr_t*)&state);
	return read<uintptr_t>(uworld_ptr);
}


struct FText
{
	char _padding_[0x28];
	PWCHAR Name;
	DWORD Length;
};

