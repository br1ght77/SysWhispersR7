#include "<BASENAME>.h"


// Note that compiler optimizations need to be disabled for SyscallStub() and all the rdi...() API functions
// to make sure the stack is setup in a way that can be handle by DoSyscall() assembly code.
#pragma optimize( "g", off )
#ifdef __MINGW32__
#pragma GCC push_options
#pragma GCC optimize ("O0")
#endif

//
// Main stub that is called by all the native API functions
//
#pragma warning(disable: 4100) // warning C4100: unreferenced formal parameter
NTSTATUS SyscallStub(Syscall* pSyscall, ...) {
	return DoSyscall();
}
#pragma warning(default: 4100)



#ifdef __MINGW32__
#pragma GCC pop_options
#endif
#pragma optimize( "g", on )

DWORD SW3_HashSyscall(PCSTR FunctionName, DWORD mode)
{
	DWORD i = 0;
	DWORD j = 0;
	DWORD Hash = SW3_SEED;
	char wide[20] = { 0 };
	if (mode == 1) {
		while (FunctionName[i])
		{
			wide[j] = *(WORD*)((ULONG_PTR)FunctionName + i);
			i += 2;
			j++;
		}
		FunctionName = wide;

	}
	i = 0;
	while (FunctionName[i])
	{
		WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
		Hash ^= PartialName + SW3_ROR8(Hash);
	}

	return Hash;
}
//
// Extract the system call trampoline address in ntdll.dll
//
BOOL ExtractTrampolineAddress(PVOID pStub, Syscall *pSyscall) {
	if (pStub == NULL || pSyscall == NULL)
		return FALSE;

	// If the stub starts with the right bytes, check the syscall number to make sure it is the expected stub.
	// Ignore this check if it is hooked (it starts with byte `0xe9`) and assume this is the expected stub.
	// Finally, return the address right after the syscall number or the hook.

#ifdef _WIN64
	// On x64 Windows, the function starts like this:
	// 4C 8B D1          mov r10, rcx
	// B8 96 00 00 00    mov eax, 96h   ; syscall number
	//
	// If it is hooked a `jmp <offset>` will be found instead
	// E9 4B 03 00 80    jmp 7FFE6BCA0000
	// folowed by the 3 remaining bytes from the original code:
	// 00 00 00
	if (*(PUINT32)pStub == 0xb8d18b4c && *(PUINT16)((PBYTE)pStub + 4) == pSyscall->dwSyscallNr || *(PBYTE)pStub == 0xe9) {
		pSyscall->pStub = (LPVOID)((PBYTE)pStub + 8);
		return TRUE;
	}
#else
	// On x86 ntdll, it starts like this:
	// B8 F1 00 00 00    mov     eax, 0F1h   ; syscall number
	//
	// If it is hooked a `jmp <offset>` will be found instead
	// E9 99 00 00 00    jmp     775ECAA1
	if (*(PBYTE)pStub == 0xb8 && *(PUINT16)((PBYTE)pStub + 1) == pSyscall->dwSyscallNr || *(PBYTE)pStub == 0xe9) {
		pSyscall->pStub = (LPVOID)((PBYTE)pStub + 5);
		return TRUE;
	}
#endif

	return FALSE;
}

//
// Retrieve the syscall data for every functions in Syscalls and UtilitySyscalls arrays of Syscall structures.
// It goes through ntdll exports and compare the hash of the function names with the hash contained in the structures.
// For each matching hash, it extract the syscall data and store it in the structure.
//
BOOL getSyscalls(PVOID pNtdllBase, Syscall* Syscalls[], DWORD dwSyscallSize) {
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS pNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	PDWORD pdwAddrOfNames = NULL, pdwAddrOfFunctions = NULL;
	PWORD pwAddrOfNameOrdinales = NULL;
	DWORD dwIdxfName = 0, dwIdxSyscall = 0;
	SYSCALL_LIST SyscallList;

	pDosHdr = (PIMAGE_DOS_HEADER)pNtdllBase;
	pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHdr->e_lfanew);
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);

	pdwAddrOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfFunctions);
	pdwAddrOfNames = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNames);
	pwAddrOfNameOrdinales = (PWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNameOrdinals);

	// Populate SyscallList with unsorted Zw* entries.
	DWORD i = 0;
	SYSCALL_ENTRY* Entries = SyscallList.Entries;
	for (dwIdxfName = 0; dwIdxfName < pExportDir->NumberOfNames; dwIdxfName++) {
		PCHAR FunctionName = (PCHAR)((PBYTE)pNtdllBase + pdwAddrOfNames[dwIdxfName]);

		// Selecting only system call functions starting with 'Zw'
		if (*(USHORT*)FunctionName == 0x775a)
		{
			Entries[i].dwCryptedHash = SW3_HashSyscall(FunctionName,0);
			Entries[i].pAddress = (PVOID)((PBYTE)pNtdllBase + pdwAddrOfFunctions[pwAddrOfNameOrdinales[dwIdxfName]]);

			if (++i == MAX_SYSCALLS)
				break;
		}
	}

	// Save total number of system calls found
	SyscallList.dwCount = i;

	// Sort the list by address in ascending order.
	for (i = 0; i < SyscallList.dwCount - 1; i++)
	{
		for (DWORD j = 0; j < SyscallList.dwCount - i - 1; j++)
		{
			if (Entries[j].pAddress > Entries[j + 1].pAddress)
			{
				// Swap entries.
				SYSCALL_ENTRY TempEntry;

				TempEntry.dwCryptedHash = Entries[j].dwCryptedHash;
				TempEntry.pAddress = Entries[j].pAddress;

				Entries[j].dwCryptedHash = Entries[j + 1].dwCryptedHash;
				Entries[j].pAddress = Entries[j + 1].pAddress;

				Entries[j + 1].dwCryptedHash = TempEntry.dwCryptedHash;
				Entries[j + 1].pAddress = TempEntry.pAddress;
			}
		}
	}

	// Find the syscall numbers and trampolins we need
	for (dwIdxSyscall = 0; dwIdxSyscall < dwSyscallSize; ++dwIdxSyscall) {
		for (i = 0; i < SyscallList.dwCount; ++i) {
			if (SyscallList.Entries[i].dwCryptedHash == Syscalls[dwIdxSyscall]->dwCryptedHash) {
				Syscalls[dwIdxSyscall]->dwSyscallNr = i;
				if (!ExtractTrampolineAddress(SyscallList.Entries[i].pAddress, Syscalls[dwIdxSyscall]))
					return FALSE;
				break;
			}
		}
	}

	// Last check to make sure we have everything we need
	for (dwIdxSyscall = 0; dwIdxSyscall < dwSyscallSize; ++dwIdxSyscall) {
		if (Syscalls[dwIdxSyscall]->pStub == NULL)
			return FALSE;
	}

	return TRUE;
}

#define DEREF( name )*(UINT_PTR *)(name)
#define NTDLLDLL_HASH   <REPLACE_NTDLLDLL_HASH>
Syscall* Syscalls[<NUMBER_FUNCTIONS>];

void Init_syscall(){
	USHORT usCounter;
	// the initial location of this image in memory
	ULONG_PTR uiLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;
	// NTDLL base address to be used to get syscall numbers and trampolins
	PVOID pNtdllBase = NULL;

	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;


#ifdef _WIN64

	uiBaseAddress = __readgsqword(0x60);
#else
#ifdef WIN_ARM
	uiBaseAddress = *(DWORD*)((BYTE*)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#else // _WIN32
	uiBaseAddress = __readfsdword(0x30);
#endif
#endif

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

	// get the first entry of the InMemoryOrder module list
	uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
	while (uiValueA)
	{
		// get pointer to current modules name (unicode string)
		uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
		// set bCounter to the length for the loop
		usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		uiValueC = 0;
		// compute the hash of the module name...
		ULONG_PTR uiValueC = SW3_HashSyscall(uiValueB,1);

		if ((DWORD)uiValueC == NTDLLDLL_HASH)
		{
			// get this modules base address
			pNtdllBase = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;
			break;
		}
		uiValueA = DEREF(uiValueA);
	}
    <SYSCALL_DEFINE>
    getSyscalls(pNtdllBase, Syscalls, (sizeof(Syscalls) / sizeof(Syscalls[0])));
}
