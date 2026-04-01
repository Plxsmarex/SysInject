#ifndef SHELLCODE_TOOLKIT
#define SHELLCODE_TOOLKIT

// Use createstring to put a string in the .text section
#define createstring __attribute__((section(".text.data"), used))

// Remove startup code and set the entry point to the base of the .text section
#define main __attribute__((section(".text.entrypoint"), used)) EntryPoint


// GetPEBAddress: returns the address of the Process Environment Block, or 0 on failure
static void *GetPEBAddress(void)
{
	void *PEB_Address = 0;
	asm volatile("movq %%gs:0x60, %0" : "=r"(PEB_Address));
	return PEB_Address;
}


// HashASCII: function to hash a small amount of ASCII data
static unsigned int HashASCII(unsigned char *Data)
{
	unsigned int Hash = 9327;
	for (unsigned char *Pointer = Data; *Pointer; ++Pointer)
	{
		Hash = (Hash * 37) + (*Pointer);
	}
	return Hash;
}


// HashWide: function to hash a small amount of Wide data
static unsigned int HashWide(unsigned short *Wide_Data)
{
	unsigned int Hash = 9327;
	for (unsigned short *Wide_Pointer = Wide_Data; *Wide_Pointer != 0; ++Wide_Pointer)
	{
		unsigned char Wide_Byte = (*Wide_Pointer);
		Hash = (Hash * 37) + Wide_Byte;
	}
	return Hash;
}


// GetModuleAddress: returns the address of the target module, or 0 if not found
// PEB_Address = address of the Process Environment Block
// Target_Module_Hash = hash of the target module
static void *GetModuleAddress(void *PEB_Address, unsigned int Target_Module_Hash)
{
	// PEB->Ldr
	unsigned char *PEB_Ldr = *(unsigned char**)((unsigned char*)PEB_Address + 0x18);
	// Ldr->InMemoryOrderModuleList
	unsigned char *PEB_InMemoryOrderModuleList = PEB_Ldr + 0x20;
	// Current module list entry
	unsigned char *Current_List_Entry = *(unsigned char**)PEB_InMemoryOrderModuleList;
	// Loop until back at the start of the module list
	while (Current_List_Entry != (unsigned char*)PEB_InMemoryOrderModuleList)
	{
		unsigned short *Name_Buffer = *(unsigned short**)(Current_List_Entry + 0x50);
		// Calculate the current listed module's hash
		unsigned int Current_Module_Hash = HashWide(Name_Buffer);
		// If Hash of current listed module is target Hash, return its address
		if (Current_Module_Hash == Target_Module_Hash)
		{
			void *Target_Module_Address = *(void**)(Current_List_Entry + 0x20);
			return Target_Module_Address;
		}
		// Move to next entry in the module list
		Current_List_Entry = *(unsigned char**)(Current_List_Entry);
	}
	// Return 0 if nothing was found
	return 0;
}


// GetExportAddress: returns the address of the target export, or 0 if not found
// Module_Address = address of the module which has the export
// Target_Export_Hash = hash of the target export
static void *GetExportAddress(void *Module_Address, unsigned int Target_Export_Hash)
{
	unsigned char *Optional_Header = Module_Address + *(unsigned int*)(Module_Address + 0x3C) + 24;
	// Choose right offset depending on if it's a 32 bit module or 64 bit
	unsigned int Export_Address = (*(unsigned short*)Optional_Header == 0x20B) ? *(unsigned int*)(Optional_Header + 0x70) : *(unsigned int*)(Optional_Header + 0x60);
	// Locate the Export Directory
	unsigned char *Export_Directory = Module_Address + Export_Address;
	// Get required info
	unsigned int Number_Of_Names = *(unsigned int*)(Export_Directory + 0x18);
	unsigned int Address_Of_Functions = *(unsigned int*)(Export_Directory + 0x1C);
	unsigned int Address_Of_Names = *(unsigned int*)(Export_Directory + 0x20);
	unsigned int Address_Of_Ordinals = *(unsigned int*)(Export_Directory + 0x24);
	// Repeat for every exported function
	for (unsigned int Index = 0; Index < Number_Of_Names; Index++)
	{
		unsigned char *Name = (unsigned char*)((unsigned char*)Module_Address + *(unsigned int*)((unsigned char*)Module_Address + Address_Of_Names + Index * 4));
		// Calculate the current export's hash
		unsigned int Current_Export_Hash = HashASCII(Name);
		// If Hash of current export is target Hash, return its address
		if (Current_Export_Hash == Target_Export_Hash)
		{
			unsigned short Ordinal = *(unsigned short*)((unsigned char*)Module_Address + Address_Of_Ordinals + Index * 2);
			void *Target_Export_Address = (unsigned char*)Module_Address + *(unsigned int*)((unsigned char*)Module_Address + Address_Of_Functions + Ordinal * 4);
			return Target_Export_Address;
		}
	}
	// Return 0 if nothing was found
	return 0;
}



#endif
