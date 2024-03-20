
#include "stdafx.h"
#include "string_parser.h"
#include "windows.h"
#include <sys/types.h>
#include "dirent.h"
#include <errno.h>
#include <vector>
#include <string>
#include <iostream>
#include "Shlwapi.h"
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include "process_strings.h"

using namespace std;

static BOOL Is64BitWindows() {
#if defined(_WIN64)
	return TRUE;
#elif defined(_WIN32)
	BOOL isWow64 = FALSE;
	return IsWow64Process(GetCurrentProcess(), &isWow64) && isWow64;
#else
	return FALSE;
#endif
}

static bool isElevated(HANDLE h_Process) {
	HANDLE h_Token;
	TOKEN_ELEVATION t_TokenElevation;
	TOKEN_ELEVATION_TYPE e_ElevationType;
	DWORD dw_TokenLength;

	if (OpenProcessToken(h_Process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h_Token)) {
		std::unique_ptr<TOKEN_ELEVATION> tokenElevation(new TOKEN_ELEVATION());
		if (GetTokenInformation(h_Token, TokenElevation, tokenElevation.get(), sizeof(TOKEN_ELEVATION), &dw_TokenLength)) {
			if (tokenElevation->TokenIsElevated != 0) {
				std::unique_ptr<TOKEN_ELEVATION_TYPE> elevationType(new TOKEN_ELEVATION_TYPE());
				if (GetTokenInformation(h_Token, TokenElevationType, elevationType.get(), sizeof(TOKEN_ELEVATION_TYPE), &dw_TokenLength)) {
					if (*elevationType == TokenElevationTypeFull || *elevationType == TokenElevationTypeDefault) {
						return true;
					}
				}
			}
		}
	}

	return false;
}

static bool getMaximumPrivileges(HANDLE h_Process) {
	HANDLE h_Token;
	DWORD dw_TokenLength;
	if (OpenProcessToken(h_Process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h_Token)) {
		DWORD dw_Size = sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES) * 100;
		std::unique_ptr<BYTE[]> buffer(new BYTE[dw_Size]);
		TOKEN_PRIVILEGES* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.get());
		if (GetTokenInformation(h_Token, TokenPrivileges, privileges, dw_Size, &dw_TokenLength)) {
			for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
				privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
			}
			if (AdjustTokenPrivileges(h_Token, FALSE, privileges, dw_Size, nullptr, nullptr)) {
				return true;
			}
		}
	}
	return false;
}

int _tmain(int argc, _TCHAR* argv[])
{
	//char buf[1000000];
	//setvbuf(stdout, buf, _IOFBF, sizeof(buf));

	// Process the flags	
	WCHAR* filter = nullptr;
	bool flagHelp = false;
	bool flagHeader = true;
	bool flagFile = false;
	bool flagFilePath = false;
	bool flagPrintType = false;
	bool flagAsmOnly = false;
	bool flagRawOnly = false;
	bool flagAsciiOnly = false;
	bool flagUnicodeOnly = false;
	bool pipedInput = !_isatty(_fileno(stdin));
	bool flagPidDump = false;
	bool flagSystemDump = false;
	bool flagRecursive = false;
	bool flagEscape = false;
	bool flagEcoMode = false;
	bool flagNotPage = false;
	int minCharacters = 4;

	if( argc <= 1 && !pipedInput )
		flagHelp = true;
	for( int i = 1; i < argc; i++ )
	{
		if( lstrcmp(argv[i],L"--help") == 0 || lstrcmp(argv[i],L"-help") == 0 || lstrcmp(argv[i],L"-h") == 0 || lstrcmp(argv[i],L"--h") == 0)
			flagHelp = true;
		else if( lstrcmp(argv[i],L"-raw") == 0 )
			flagRawOnly = true;
		else if( lstrcmp(argv[i],L"-p") == 0 )
			flagPidDump = true;
		else if( lstrcmp(argv[i],L"-a") == 0 )
			flagAsciiOnly = true;
		else if( lstrcmp(argv[i],L"-u") == 0 )
			flagUnicodeOnly = true;
		else if (lstrcmp(argv[i], L"-eco") == 0)
			flagEcoMode = true;
		else if (lstrcmp(argv[i], L"-notpage") == 0)
			flagNotPage = true;
		else if( lstrcmp(argv[i],L"-l") == 0 )
		{
			if(  i + 1 < argc )
			{
				int result = _wtoi(argv[i+1]);
				if( result >= 3 )
				{
					minCharacters = result;
				}else{
					fprintf(stderr,"Failed to parse -l argument. The string size must be 3 or larger.\n");
					exit(0);
				}
				i++;
			}else{
				fprintf(stderr,"Failed to parse -l argument. It must be preceeded by a number.\n");
				exit(0);
			}
		}else{
			if( filter == NULL )
			{
				filter = argv[i];
			}
			else
			{
				fprintf(stderr,"Failed to parse argument number %i, '%S'.\n", i, argv[i]);
				exit(0);
			}
		}
	}

	STRING_OPTIONS options;
	options.pagination = true;
	options.ecoMode = false;
	options.printAsciiOnly = false;
	options.printUnicodeOnly = false;
	options.printNormal = false;

	if (!flagPidDump) {
		flagHelp = true;
	}

	if (flagEcoMode && flagNotPage) {
		fprintf(stderr, "You cannot select Eco Mode and Not Pagination at the same time.\n");
		exit(0);
	}
	options.ecoMode = flagEcoMode;
	options.pagination = !flagNotPage;

	if (flagRawOnly) {
		options.printNormal = true;
	}
	else {
		if (flagAsciiOnly && flagUnicodeOnly) {
			fprintf(stderr, "Warning: Default conditions extract both Unicode and ASCII strings. There is no need to use both '-a' and '-u' flags at the same time.\n");
		}
		else {
			options.printAsciiOnly = flagAsciiOnly;
			options.printUnicodeOnly = flagUnicodeOnly;
		}
		if (!flagAsciiOnly && !flagUnicodeOnly && !flagRawOnly) {
			options.printNormal = true;
		}
	}

	options.minCharacters = minCharacters;

	if (flagHelp) {
		std::cout << "xxstrings is a tool to dump strings from the memory of a process. Some parts of the code are based on the famous strings2 by Geoff McDonald." << std::endl;
		std::cout << "Usage:" << std::endl;
		std::cout << "strings.exe -p <PID> <flags>" << std::endl << std::endl;
		std::cout << "Flags:" << std::endl;
		std::cout << " -p pid" << std::endl << "\tDefines the Process ID from which the strings will be extracted." << std::endl;
		std::cout << " -eco" << std::endl << "\tActivate Eco Mode. This will only use paging in processes with a job size greater than 500 MB." << std::endl;
		std::cout << " -notpage" << std::endl << "\tDisables the paging that is enabled by default." << std::endl;
		std::cout << " -raw" << std::endl << "\tOnly prints the regular ascii/unicode strings." << std::endl;
		std::cout << " -a" << std::endl << "\tPrints only ascii strings." << std::endl;
		std::cout << " -u" << std::endl << "\tPrints only unicode strings." << std::endl;
		std::cout << " -l [numchars]" << std::endl << "\tMinimum number of characters that is" << std::endl << "\ta valid string. Default is 4." << std::endl;
	}
	else {
		std::unique_ptr<string_parser> parser(new string_parser(options));

		if (flagPidDump) {
			if (Is64BitWindows() && sizeof(void*) == 4) {
				wcerr << L"WARNING: You are running a 32-bit version on a 64-bit system." << endl;
			}

			getMaximumPrivileges(GetCurrentProcess());

			std::unique_ptr<process_strings> process(new process_strings(parser.get()));

			if (filter != nullptr) {
				bool isHex = false;
				std::wstring filterStr(filter);
				if (filterStr.size() >= 2 && filterStr.substr(0, 2) == L"0x") {
					filterStr = filterStr.substr(2);
					isHex = true;
				}

				try {
					unsigned int PID;
					if ((isHex && std::stoi(filterStr, nullptr, 16)) || (!isHex && (std::stoi(filterStr) > 0)) > 0) {
						PID = std::stoul(filterStr, nullptr, isHex ? 16 : 10);
						process->dump_process(PID, options.ecoMode, options.pagination);
					}
					else {
						wcerr << L"Failed to parse filter argument as a valid PID: " << filterStr << endl;
					}
				}
				catch (const std::invalid_argument&) {
					wcerr << L"Failed to parse filter argument as a valid PID: " << filterStr << endl;
				}
				catch (const std::out_of_range&) {
					wcerr << L"Failed to parse filter argument as a valid PID: " << filterStr << endl;
				}
			}
			else {
				wcerr << L"Error. No Process ID was specified." << endl;
			}
		}
	}

	return 0;
}
