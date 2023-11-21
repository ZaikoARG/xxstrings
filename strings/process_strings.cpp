#include "StdAfx.h"
#include "process_strings.h"
#include "string_parser.h"


static bool IsWin64(HANDLE process)
{
	BOOL retVal;
	if (IsWow64Process(process, &retVal))
	{
		return retVal;
	}
	PrintLastError(L"IsWow64Process");
	return false;
}

bool process_strings::dump_process(DWORD pid, bool ecomode, bool pagination)
{
	// Open the process
	HANDLE ph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
	if (ph != NULL)
	{
		// Assign the process name
		TCHAR* process_name_w = new TCHAR[0x100];
		process_name_w[0] = 0;
		GetModuleBaseName(ph, 0, process_name_w, 0x100);
		char* process_name = new char[0x100];
		process_name[0] = 0;

		// Convert from wchar to char filename
		size_t convertedChars = 0;
		errno_t err = wcstombs_s(&convertedChars, process_name, 0x100, process_name_w, _TRUNCATE);

		// Generate the module list
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
		if (hSnapshot != INVALID_HANDLE_VALUE)
		{
			this->generateModuleList(hSnapshot);
			CloseHandle(hSnapshot);

			// Walk through the process heaps, extracting the strings
			bool result = this->processAllHeaps(ph, process_name, ecomode, pagination);

			delete[] process_name;
			return result;
		}
		else
		{
			fprintf(stderr, "Failed to gather module information for process 0x%x (%i). ", pid, pid);
			PrintLastError(L"dump_process");
		}

		delete[] process_name;
		return false;
	}
	else
	{
		fprintf(stderr, "Failed to open process 0x%x (%i). ", pid, pid);
		PrintLastError(L"dump_process");
	}

	// Add a default return statement for cases where none of the conditions are met
	return false;
}

process_strings::process_strings(string_parser* parser)
{
	this->parser = parser;
}

bool process_strings::processAllHeaps(HANDLE ph, char* process_name, bool ecomode, bool pagination)
{
	// Set the max address of the target process. Assume it is a 64 bit process.
	__int64 maxAddress = 0;
	maxAddress = 0x7ffffffffff;
	// Walk the process heaps
	__int64 address = 0;
	bool paging = true;
	MEMORY_BASIC_INFORMATION mbi;
	PROCESS_MEMORY_COUNTERS_EX pmi;
	GetProcessMemoryInfo(ph, (PROCESS_MEMORY_COUNTERS*)&pmi, sizeof(pmi));

	if (ecomode == true) {
		while (address < maxAddress)
		{
			if (pmi.PrivateUsage < 524288000) {
				paging = false;
			}
			// Load this heap information
			__int64 blockSize = VirtualQueryEx(ph, (LPCVOID)address, (_MEMORY_BASIC_INFORMATION*)&mbi, sizeof(_MEMORY_BASIC_INFORMATION64));
			__int64 newAddress = (__int64)mbi.BaseAddress + (__int64)mbi.RegionSize + (__int64)1;
			if (newAddress <= address)
				break;
			address = newAddress;

			if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && mbi.RegionSize <= 5000000 && paging == true || mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && paging == false)
			{
				// Process this heap

				// Read in the heap
				unsigned char* buffer = new unsigned char[mbi.RegionSize];
				if (buffer != NULL)
				{
					__int64 numRead = 0;
					bool result = ReadProcessMemory(ph, (LPCVOID)mbi.BaseAddress, buffer, mbi.RegionSize, (SIZE_T*)&numRead);

					//fprintf(stderr,"Current address: %016llX\n",mbi.BaseAddress);
					if (numRead > 0)
					{
						if (numRead != static_cast<unsigned __int64>(mbi.RegionSize))
						{
							DWORD errorMessageID = GetLastError();
							LPVOID errorMessageBuffer = nullptr;

							FormatMessage(
								FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
								nullptr,
								errorMessageID,
								0, // Default language
								reinterpret_cast<LPWSTR>(&errorMessageBuffer),
								0,
								nullptr
							);

							fprintf(stderr, "Failed read full heap from address 0x%016llX: %s. Only %lld of expected %lld bytes were read.\n",
								reinterpret_cast<uintptr_t>(mbi.BaseAddress), static_cast<const wchar_t*>(errorMessageBuffer),
								static_cast<long long>(numRead), static_cast<long long>(mbi.RegionSize));

							LocalFree(errorMessageBuffer);
						}

						// Print the strings from this heap
						parser->parse_block(buffer, numRead, process_name);
					}
					else if (!result)
					{
						DWORD errorMessageID = GetLastError();
						LPVOID errorMessageBuffer = nullptr;

						FormatMessage(
							FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
							nullptr,
							errorMessageID,
							0, // Default language
							reinterpret_cast<LPWSTR>(&errorMessageBuffer),
							0,
							nullptr
						);

						fprintf(stderr, "Failed to read from address 0x%p. %s", mbi.BaseAddress, static_cast<const wchar_t*>(errorMessageBuffer));

						LocalFree(errorMessageBuffer);
					}

					// Cleanup
					delete[] buffer;
				}
				else {
					fprintf(stderr, "Failed to allocate space of %lld for reading in a heap.", static_cast<long long>(mbi.RegionSize));
				}
			}
		}

		return true;
	}
	else
	{
		if (pagination == false) {
			paging = false;
		}
		while (address < maxAddress)
		{
			// Load this heap information
			__int64 blockSize = VirtualQueryEx(ph, (LPCVOID)address, (_MEMORY_BASIC_INFORMATION*)&mbi, sizeof(_MEMORY_BASIC_INFORMATION64));
			__int64 newAddress = (__int64)mbi.BaseAddress + (__int64)mbi.RegionSize + (__int64)1;
			if (newAddress <= address)
				break;
			address = newAddress;

			if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && mbi.RegionSize <= 5000000 && paging == true || mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && paging == false)
			{
				// Process this heap

				// Read in the heap
				unsigned char* buffer = new unsigned char[mbi.RegionSize];
				if (buffer != NULL)
				{
					__int64 numRead = 0;
					bool result = ReadProcessMemory(ph, (LPCVOID)mbi.BaseAddress, buffer, mbi.RegionSize, (SIZE_T*)&numRead);

					char errorMsg[256]{}; // Adjust the size as needed

					//fprintf(stderr,"Current address: %016llX\n",mbi.BaseAddress);
					if (numRead > 0)
					{
						if (numRead != static_cast<unsigned __int64>(mbi.RegionSize))
							fprintf(stderr, "Failed read full heap from address 0x%016llX: %s. Only %lld of expected %lld bytes were read.\n",
								mbi.BaseAddress, errorMsg, static_cast<long long>(numRead), static_cast<long long>(mbi.RegionSize));

						// Print the strings from this heap
						parser->parse_block(buffer, numRead, process_name);
					}
					else if (!result) {
						fprintf(stderr, "Failed to read from address 0x%016llX. %s", mbi.BaseAddress, errorMsg);
						PrintLastError(L"ReadProcessMemory");
					}

					// Cleanup
					delete [] buffer;
				}
				else {
					fprintf(stderr, "Failed to allocate space of %lld for reading in a heap.", static_cast<long long>(mbi.RegionSize));
				}
			}
		}

		return true;
	}
}

void process_strings::generateModuleList(HANDLE hSnapshot)
{
	MODULEENTRY32 tmpModule;
	tmpModule.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hSnapshot, &tmpModule))
	{
		// Add this i_module to our array
		tmpModule.dwSize = sizeof(MODULEENTRY32);
		modules.Add(new module(tmpModule));

		while (Module32Next(hSnapshot, &tmpModule))
		{
			// Add this i_module to our array
			modules.Add(new module(tmpModule));
			tmpModule.dwSize = sizeof(MODULEENTRY32);
		}
	}
}

process_strings::~process_strings(void)
{
}
