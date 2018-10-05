#pragma warning(disable:4305)

#include <windows.h>
#include <stdio.h>
#include <malloc.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004 //status code for more buffer
#define ARRAY_SIZE (1024*1024) //1MB buffer

/// <summary>
/// _SYSTEM_INFORMATION_CLASS and data structure
/// </summary>
//win10rs4.17134
#define SystemHandleInformation 16			//_SYSTEM_HANDLE_INFORMATION
#define SystemExtendedHandleInformation 64	//_SYSTEM_HANDLE_INFORMATION_EX

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
}SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX 
{
	PVOID Object;
	ULONG UniqueProcessId;
	ULONG HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG  HandleAttributes;
	ULONG  Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX 
{
	ULONG NumberOfHandles;
	ULONG Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;


/// <summary>
/// ntdll!NtQuerySystemInformation
/// </summary>
/// <param name="SystemInformationClass">_SYSTEM_INFORMATION_CLASST</param>
/// <param name="SystemInformation">Data structure for systen information we want to query</param>
/// <param name="SystemInformationLength">buffer length</param>
/// <param name="ReturnLength">optional, if the buffer is not big enough, return the length required</param>
/// <returns>NTSTATUS</returns>

typedef LONG (*PNT_QUERY_SYSTEM_INFORMATION)
(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

/// <summary>
/// Get kernel handle object address from token handle
/// </summary>
/// <param name="hPid">process id we're interested in</param>
/// <param name="hHandle">token handle for the process</param>
/// <returns>PVOID, kernel object pointer</returns>

PVOID 
GetHandleObjectAddressFromHandle(
	HANDLE hPid,
	HANDLE hHandle )
{
	//get ntdll module handle by GetModuleHandle in order to get exported nt functions
	HMODULE hNtdll = NULL;
	if ((hNtdll = GetModuleHandle("ntdll.dll")) == NULL)
	{
		printf("[-] GetModuleHandle(ntdll.dll) failed: %08x\n", GetLastError());
		goto Exit;
	}

	//get the exported function pointer of NtQuerySystemInformation from ntdll
	PNT_QUERY_SYSTEM_INFORMATION pNtQuerySystemInformation = NULL;
	if ((pNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)(GetProcAddress(hNtdll, "NtQuerySystemInformation"))) == NULL)
	{
		printf("[-] GetProcAddress(NtQuerySystemInformation) failed: %08x\n", GetLastError());
		goto Exit;
	}

	//query system handle information 
	PSYSTEM_HANDLE_INFORMATION pSystemHandleInformationBuffer = NULL;
	ULONG ulSystemInformationLength = ARRAY_SIZE;
	ULONG ulReturnLength = 0;
	LONG status;

	pSystemHandleInformationBuffer = (PSYSTEM_HANDLE_INFORMATION)malloc(ulSystemInformationLength);
	if (!pSystemHandleInformationBuffer)
	{
		printf("[-] malloc(%u) failed\n", ulSystemInformationLength);
		goto Exit;
	}

	while (TRUE)
	{
		status = pNtQuerySystemInformation(
			SystemHandleInformation,
			pSystemHandleInformationBuffer,
			ulSystemInformationLength,
			&ulReturnLength);

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			//free the previous buffer 
			if (pSystemHandleInformationBuffer) {
				free(pSystemHandleInformationBuffer);
			}

			//increase the size since we may trigger more handle creation
			ulSystemInformationLength *= 2;

			//reallocate the buffer
			pSystemHandleInformationBuffer = (PSYSTEM_HANDLE_INFORMATION)malloc(ulSystemInformationLength);
			if (!pSystemHandleInformationBuffer)
			{
				printf("[-] malloc(%u) failed\n", ulSystemInformationLength);
				goto Exit;
			}

		}
		else if (NT_SUCCESS(status))
		{
			break;
		}
		else
		{
			printf("[-] NtQuerySystemInformation(SystemHandleInformation) failed: %08x\n", status);
			goto Exit;
		}
	}
	
	//iterate the handle table until we find the required handle information
	PVOID pObject = NULL;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO pSystemHandleTableEntryInfo = NULL;
	pSystemHandleTableEntryInfo = pSystemHandleInformationBuffer->Handles;

	for (unsigned int i = 0; i < pSystemHandleInformationBuffer->NumberOfHandles; i++, pSystemHandleTableEntryInfo++)
	{
		//find the handle table entry of the process id we want
		if (pSystemHandleTableEntryInfo->UniqueProcessId != (USHORT)PtrToUlong(hPid))
		{
			continue;
		}

		//if the handle value is what we need then return the object pointer
		if (pSystemHandleTableEntryInfo->HandleValue == (USHORT)PtrToUlong(hHandle))
		{
			pObject = pSystemHandleTableEntryInfo->Object;
			goto Exit;
		}
	}


Exit:
	if (hNtdll)
	{
		CloseHandle(hNtdll);
	}

	if (pNtQuerySystemInformation)
	{
		pNtQuerySystemInformation = NULL;
	}

	if (pSystemHandleInformationBuffer)
	{
		free(pSystemHandleInformationBuffer);
	}

	if (pSystemHandleTableEntryInfo)
	{
		pSystemHandleTableEntryInfo = NULL;
	}

	return pObject;
}//GetHandleObjectAddressFromHandle()