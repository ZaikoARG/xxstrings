
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


BOOL Is64BitWindows()
{
	#if defined(_WIN64)
		return TRUE;  // 64-bit programs run only on Win64
	#elif defined(_WIN32)
		// 32-bit programs run on both 32-bit and 64-bit Windows
		// so must sniff
		BOOL f64 = FALSE;
		return IsWow64Process(GetCurrentProcess(), &f64) && f64;
	#else
		return FALSE; // Win64 does not support Win16
	#endif
}

bool isElevated(HANDLE h_Process)
{
	HANDLE h_Token;
	TOKEN_ELEVATION t_TokenElevation;
    TOKEN_ELEVATION_TYPE e_ElevationType;
	DWORD dw_TokenLength;
	
	if( OpenProcessToken(h_Process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES , &h_Token) )
	{
		if(GetTokenInformation(h_Token,TokenElevation,&t_TokenElevation,sizeof(t_TokenElevation),&dw_TokenLength))
		{
			if(t_TokenElevation.TokenIsElevated != 0)
			{
				if(GetTokenInformation(h_Token,TokenElevationType,&e_ElevationType,sizeof(e_ElevationType),&dw_TokenLength))
				{
					if(e_ElevationType == TokenElevationTypeFull || e_ElevationType == TokenElevationTypeDefault)
					{
						return true;
					}
				}
			}
		}
	}

    return false;
}



bool getMaximumPrivileges(HANDLE h_Process)
{
	HANDLE h_Token;
	DWORD dw_TokenLength;
	if( OpenProcessToken(h_Process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES , &h_Token) )
	{
		// Read the old token privileges
		TOKEN_PRIVILEGES* privilages = new TOKEN_PRIVILEGES[100];
		if( GetTokenInformation(h_Token, TokenPrivileges, privilages,sizeof(TOKEN_PRIVILEGES)*100,&dw_TokenLength) )
		{
			// Enable all privileges
			for( int i = 0; i < privilages->PrivilegeCount; i++ )
			{
				privilages->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
			}
			
			// Adjust the privilges
			if(AdjustTokenPrivileges( h_Token, false, privilages, sizeof(TOKEN_PRIVILEGES)*100, NULL, NULL  ))
			{
				delete[] privilages;
				return true;
			}
		}
		delete[] privilages;
	}
	return false;
}

int _tmain(int argc, _TCHAR* argv[])
{
	//char buf[1000000];
	//setvbuf(stdout, buf, _IOFBF, sizeof(buf));

	// Process the flags	
	WCHAR* filter = NULL;
	bool flagHelp = false;
	bool flagHeader = true;
	bool flagFile = false;
	bool flagFilePath = false;
	bool flagPrintType = false;
	bool flagAsmOnly = false;
	bool flagRawOnly = false;
	bool flagAsciiOnly = false;
	bool flagUnicodeOnly = false;
	bool pipedInput = !_isatty( _fileno( stdin ) );
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
				// Try to parse the number of characters
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
			// This is an unassigned argument
			if( filter == NULL )
			{
				filter = argv[i];
			}
			else
			{
				// This argument is an error, we already found our filter.
				fprintf(stderr,"Failed to parse argument number %i, '%S'.\n", i, argv[i]);
				exit(0);
			}
		}
	}

	// Fill out the options structure based on the flags
	STRING_OPTIONS options;
	options.pagination = true;
	options.ecoMode = false;
	options.printAsciiOnly = false;
	options.printUnicodeOnly = false;
	options.printNormal = false;

	if (flagPidDump != true) {
		flagHelp = true;
	}


	if (flagEcoMode)
		options.ecoMode = true;

	if (flagNotPage)
		options.pagination = false;

	if (flagNotPage && flagEcoMode)
	{
		fprintf(stderr, "You cannot select Eco Mode and Not Pagination at the same time.\n");
		exit(0);
	}


	if( flagRawOnly )
		options.printNormal = true;
	
	if( flagAsciiOnly && flagUnicodeOnly )
	{
		fprintf(stderr,"Warning. Default conditions extract both unicode and ascii strings. There is no need to use both '-a' and '-u' flags at the same time.\n");
	}else{
		if( flagAsciiOnly )
			options.printAsciiOnly = true;
		if( flagUnicodeOnly )
			options.printUnicodeOnly = true;
	}

	if (flagAsciiOnly != true && flagUnicodeOnly != true && flagRawOnly != true) {
		options.printNormal = true;
	}
	


	options.minCharacters = minCharacters;

	if( flagHelp )
	{
		printf("xxstrings is a tool to dump strings from the memory of a process. Some parts of the code is based on the famous strings2 by Geoff McDonald.\n");
		printf("This tool has been created by ZaikoARG\n\n");
		printf("Usage:\n");
		printf("xxstrings.exe -p <PID> <flags>\n\n");
		printf("Flags:\n");
		printf(" -p pid\n\tDefines the Process ID from which the strings will be extracted.\n");
		printf(" -eco\n\tActivate Eco Mode. This will only use paging in processes with a job size greater than 500 MB.\n");
		printf(" -notpage\n\tDisables the paging that is enabled by default.\n");
		printf(" -raw\n\tOnly prints the regular ascii/unicode strings.\n");
		printf(" -a\n\tPrints only ascii strings.\n");
		printf(" -u\n\tPrints only unicode strings.\n");
		printf(" -l [numchars]\n\tMinimum number of characters that is\n\ta valid string. Default is 4.\n");
	}else{
		// Create the string parser object
		string_parser* parser = new string_parser(options);

		if (flagPidDump)
		{
			// Warn if running in 32 bit mode on a 64 bit OS
			if( Is64BitWindows() && sizeof(void*) == 4 )
			{
				fprintf(stderr, "WARNING: You are running a 32-bit version on a 64-bit system.\n\n");
			}

			// Elevate strings2 to the maximum privilges
			getMaximumPrivileges( GetCurrentProcess() );

			// Create a process string dump class
			process_strings* process = new process_strings(parser);

			if( flagPidDump )
			{
				// Extract all strings from the specified process
				if( filter != NULL )
				{
					// Check the prefix
					bool isHex = false;
					wchar_t* prefix = new wchar_t[3];
					memcpy(prefix, filter, 4);
					prefix[2] = 0;

					if( wcscmp(prefix, L"0x") == 0 )
					{
						filter = &filter[2];
						isHex = true;
					}
					delete[] prefix;
					
					// Extract the pid from the string
					unsigned int PID;
					if( (isHex && swscanf(filter, L"%x", &PID) > 0) ||
						(!isHex && swscanf(filter, L"%i", &PID) > 0))
					{
						// Successfully parsed the PID
						
						// Parse the process
						process->dump_process(PID, options.ecoMode, options.pagination);

						
					}else{
						fwprintf(stderr, L"Failed to parse filter argument as a valid PID: %s.\n", filter);
					}
				}else{
					fwprintf(stderr, L"Error. No Process ID was specified.\n", filter);
				}
			}

			delete process;
		}
		
		// Cleanup the string parser
		delete parser;
	}
	

	return 0;
}

