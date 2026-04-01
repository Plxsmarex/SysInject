#ifndef SYSINJECT
#define SYSINJECT

// Required structures
typedef struct {
	unsigned long ExceptionCode;
	unsigned long ExceptionFlags;
	struct _EXCEPTION_RECORD *ExceptionRecord;
	void *ExceptionAddress;
	unsigned long NumberParameters;
	unsigned long long ExceptionInformation[15];
} EXCEPTION_RECORD;

typedef struct {
	EXCEPTION_RECORD *ExceptionRecord;
	struct _CONTEXT* ContextRecord;
} EXCEPTION_POINTERS;

typedef struct {
	unsigned long long Low;
	unsigned long long High;
} M128A;

typedef struct {
	M128A ControlWord;
	M128A StatusWord;
	M128A TagWord;
	M128A ErrorOpcode;
	M128A ErrorOffset;
	M128A ErrorSelector;
	M128A DataOffset;
	M128A DataSelector;
	M128A MxCsr;
	M128A MxCsr_Mask;
	M128A FloatRegisters[8];
	M128A XmmRegisters[16];
	unsigned char Reserved[96];
} XMM_SAVE_AREA32;

typedef struct _CONTEXT {
	unsigned long long P1Home;
	unsigned long long P2Home;
	unsigned long long P3Home;
	unsigned long long P4Home;
	unsigned long long P5Home;
	unsigned long long P6Home;
	unsigned long ContextFlags;
	unsigned long MxCsr;
	unsigned short SegCs;
	unsigned short SegDs;
	unsigned short SegEs;
	unsigned short SegFs;
	unsigned short SegGs;
	unsigned short SegSs;
	unsigned long EFlags;
	unsigned long long Dr0;
	unsigned long long Dr1;
	unsigned long long Dr2;
	unsigned long long Dr3;
	unsigned long long Dr6;
	unsigned long long Dr7;
	unsigned long long Rax;
	unsigned long long Rcx;
	unsigned long long Rdx;
	unsigned long long Rbx;
	unsigned long long Rsp;
	unsigned long long Rbp;
	unsigned long long Rsi;
	unsigned long long Rdi;
	unsigned long long R8;
	unsigned long long R9;
	unsigned long long R10;
	unsigned long long R11;
	unsigned long long R12;
	unsigned long long R13;
	unsigned long long R14;
	unsigned long long R15;
	unsigned long long Rip;
	union {
		XMM_SAVE_AREA32 FltSave;
		XMM_SAVE_AREA32 FloatSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		} FltSaveStruct;
	} FltSaveUnion;
	M128A VectorRegister[26];
	unsigned long long VectorControl;
	unsigned long long DebugControl;
	unsigned long long LastBranchToRip;
	unsigned long long LastBranchFromRip;
	unsigned long long LastExceptionToRip;
	unsigned long long LastExceptionFromRip;
} CONTEXT;

// Function types required for SysInject
typedef int  (*Type_GetThreadContext)(void *hThread, struct _CONTEXT *lpContext);
typedef long (*Type_NtContinue)(struct _CONTEXT* ContextRecord, unsigned char TestAlert);

// Global function pointers required for SysInject
Type_GetThreadContext GetThreadContext = 0;
Type_NtContinue NtContinue = 0;

// Continue execution
#define EXCEPTION_CONTINUE_EXECUTION -1

// Not our exception
#define EXCEPTION_CONTINUE_SEARCH 0



// SysInject Trap Flag
typedef struct Trap_Flag_Entry {
	struct Trap_Flag_Entry *Next_Entry;
	void *Address;
	unsigned long long Argument_Array[32];
	unsigned long long Argument_Count;
	int Mode;
} Trap_Flag_Entry;

#define MAX_TRAP_FLAG_INJECTORS 32
static Trap_Flag_Entry Trap_Flag_Pool[MAX_TRAP_FLAG_INJECTORS];
static Trap_Flag_Entry *Global_Trap_Flag_List = 0;

// Exception handler for SysInject Trap Flags
long SyscallHandler(EXCEPTION_POINTERS *Exception_Pointers)
{
	struct _CONTEXT *Context = Exception_Pointers->ContextRecord;
	unsigned long Code = Exception_Pointers->ExceptionRecord->ExceptionCode;

	if (Code == 0x80000004)
	{
		// Make sure the Trap Flag remains active
		Context->EFlags |= 0x100;

		for (Trap_Flag_Entry *Entry = Global_Trap_Flag_List; Entry; Entry = Entry->Next_Entry)
		{
			if ((void*)Context->Rip == Entry->Address)
			{
				// Injection mode
				if (Entry->Mode == 0)
				{
					// Inject first 4 arguments to registers
					// As it happens right before syscall instruction, we must use R10 instead of Rcx
					if (Entry->Argument_Count > 0) Context->R10 = Entry->Argument_Array[0];
					if (Entry->Argument_Count > 1) Context->Rdx = Entry->Argument_Array[1];
					if (Entry->Argument_Count > 2) Context->R8  = Entry->Argument_Array[2];
					if (Entry->Argument_Count > 3) Context->R9  = Entry->Argument_Array[3];

					// Inject the rest of the arguments to the stack
					for (unsigned long long Index = 4; Index < Entry->Argument_Count; ++Index)
					{
						unsigned long long *Destination = (unsigned long long*)(Context->Rsp + 0x28 + (Index - 4) * 8);
						*Destination = Entry->Argument_Array[Index];
					}

					return EXCEPTION_CONTINUE_EXECUTION;
				}

				// Ghost mode
				else if (Entry->Mode == 1)
				{
					unsigned char Bytes[2] = {0, 0};
					unsigned char *Pointer = Entry->Address;
					Bytes[0] = Pointer[0];
					Bytes[1] = Pointer[1];

					// Skip over the syscall instruction
					if (Bytes[0] == 0x0F && Bytes[1] == 0x05)
					{
						Context->Rip += 2;
						// Set return code to STATUS_TOO_MANY_SECRETS :)
						Context->Rax = 0xC0000156;
						return EXCEPTION_CONTINUE_EXECUTION;
					}
					return EXCEPTION_CONTINUE_EXECUTION;
				}
			}
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

// Add an exception target for a syscall instruction using the Trap Flag
void *SysInject(int Mode, void *Target_Address, unsigned long long Argument_Count, void *Args)
{
	Trap_Flag_Entry *Entry = 0;
	for (int Index = 0; Index < MAX_TRAP_FLAG_INJECTORS; ++Index)
	{
		if (Trap_Flag_Pool[Index].Address == 0)
		{
			// Zero the slot
			unsigned char *Pointer = (unsigned char*)&Trap_Flag_Pool[Index];
			unsigned long Remaining_Bytes = sizeof(Trap_Flag_Entry);
			while (Remaining_Bytes--)
			{
				*Pointer++ = 0;
			}

			Entry = &Trap_Flag_Pool[Index];
			break;
		}
	}

	Entry->Next_Entry = 0;
	Entry->Address = Target_Address;
	Entry->Argument_Count = (Mode == 0) ? Argument_Count : 0;
	Entry->Mode = Mode;

	if (Mode == 0 && Args && Argument_Count > 0)
	{
		unsigned long long *Source = Args;
		for (unsigned long long Index = 0; Index < Argument_Count; ++Index)
		{
			Entry->Argument_Array[Index] = Source[Index];
		}
	}

	// Insert into global list
	Entry->Next_Entry = Global_Trap_Flag_List;
	Global_Trap_Flag_List = Entry;

	// Get the context of the thread and enable the Trap Flag
	struct _CONTEXT Context;
	Context.ContextFlags = (0x00100000 | 0x00000001);
	if (GetThreadContext((void*)-2, &Context))
	{
		Context.EFlags |= 0x100;
		NtContinue(&Context, 0);
		return Entry;
	}

	// Failure!
	return 0;
}

// Remove a SysInject Trap Flag
int SysUninject(void *Handle)
{
	Trap_Flag_Entry *Target = (Trap_Flag_Entry*)Handle;
	Trap_Flag_Entry *Iteration = Global_Trap_Flag_List;
	Trap_Flag_Entry *Previous = 0;

	while (Iteration && Iteration != Target)
	{
		Previous = Iteration; Iteration = Iteration->Next_Entry;
	}

	// Not on the list
	if (!Iteration)
	{
		return 1;
	}

	if (Previous) {
		Previous->Next_Entry = Iteration->Next_Entry;
	} else {
		Global_Trap_Flag_List = Iteration->Next_Entry;
	}

	// Clear the entry slot's Address so it can be reused
	Iteration->Address = 0;

	// Clear the Trap Flag if no more entries remain
	if (Global_Trap_Flag_List == 0)
	{
		struct _CONTEXT Context;
		Context.ContextFlags = (0x00100000 | 0x00000001);
		if (GetThreadContext((void*)-2, &Context))
		{
			Context.EFlags &= ~0x100;
			NtContinue(&Context, 0);
		}
	}

	return 0;
}



#endif
