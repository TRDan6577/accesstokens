/**
 * Purpose: This was made for educational purposes as a refresher on C programming and Windows
 *          programming. It also serves as an introduction to Windows access tokens
 * Author:  Tom Daniels <github.com/trdan6577>
 * License: MPLv2. See https://github.com/TRDan6577/accesstokens and the license file for more details
*/

/****************
 * DEPENDENCIES *
****************/
// Standard header files
#include<stdlib.h>
#include<stdio.h>
#include<windows.h>

// Windows header files
#include<processthreadsapi.h>
#include<winbase.h>

// Tell the linker to add advapi32 to the list of dependencies
#pragma comment(lib, "Advapi32.lib")

#define SYSTEM_DIRECTORY_SIZE 100

/*************************
 * Function Declarations *
*************************/
BOOL PrivilegesPresent();
int ValidateCmdlineArgs(int argc, char **argv);
void PrintUsage();

/********************
 * Helper Functions *
********************/
BOOL PrivilegesPresent() {
/**
 * Purpose: Determines if the current process has the following privileges:
 * * SE_DEBUG_NAME
 * * SE_TCB_NAME
 * * SE_ASSIGNPRIMARYTOKEN_NAME
 * @return: BOOL - the return value is non-zero if all the privileges are present,
 *          zero otherwise.
*/

    HANDLE hToken = NULL;               // Access token of the current process
    LUID debugPrivLuid;                 // LUID associated with SE_DEBUG_NAME privilege
    LUID tcbPrivLuid;                   // LUID associated with the SE_TCB_NAME privilege
    LUID assignPrimaryTokenPrivLuid;    // LUID associated with the SE_ASSIGNPRIMARYTOKEN_NAME privilege
    DWORD tokenInformationLength;       // Length of the tokenInformation
    TOKEN_PRIVILEGES *pTokenPrivs;      // Privileges associated with the current process
    BOOL debugPrivilegePresent = 0;     // Is SE_DEBUG_NAME enabled?
    BOOL tcbPrivilegePresent = 0;       // Is SE_TCB_NAME enabled?
    BOOL assignPrimaryTokenPrivilegePresent = 0;  // Is SE_ASSIGNPRIMARYTOKEN_NAME enabled?
    LPVOID *tokenInformation = NULL;    // Holds the token privileges

    // Get the current process access token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken)) {
        printf("[-] Error retrieving the current process token: %d\n", GetLastError());
        goto CleanupDebug;
    }

    // Determine privileges associated with our current access token
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tokenInformationLength); // This returns ERROR_INSUFFICIENT_BUFFER since we pass in a NULL buffer
    tokenInformation = calloc(sizeof(BYTE), tokenInformationLength);
    if (!GetTokenInformation(hToken, TokenPrivileges, tokenInformation, tokenInformationLength, &tokenInformationLength)) {
        printf("[-] Error getting the privileges associated with the current process: %d\n", GetLastError());
        goto CleanupDebug;
    }
    pTokenPrivs = (TOKEN_PRIVILEGES*)tokenInformation;

    // Determine the LUID of the SE_DEBUG_NAME privilege
    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &debugPrivLuid)) {
        printf("[-] Error looking up the LUID for the SE_DEBUG_NAME privilege: %d\n", GetLastError());
        goto CleanupDebug;
    }

    // Determine the LUID of the SE_TCB_NAME privilege
    if (!LookupPrivilegeValueA(NULL, SE_TCB_NAME, &tcbPrivLuid)) {
        printf("[-] Error looking up the LUID for the SE_TCB_NAME privilege: %d\n", GetLastError());
        goto CleanupDebug;
    }

    // Determine the LUID of the SE_ASSIGNPRIMARYTOKEN_NAME privilege
    if (!LookupPrivilegeValueA(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &assignPrimaryTokenPrivLuid)) {
        printf("[-] Error looking up the LUID for the SE_ASSIGNPRIMARYTOKEN_NAME privilege: %d\n", GetLastError());
        goto CleanupDebug;
    }

    // Loop through the privileges looking for the privileges
    for (DWORD privilegeCount = 0; privilegeCount < pTokenPrivs->PrivilegeCount; privilegeCount++) {
        LUID currLuid = pTokenPrivs->Privileges[privilegeCount].Luid;

        // SE_DEBUG_NAME check
        if (currLuid.HighPart == debugPrivLuid.HighPart &&
            currLuid.LowPart == debugPrivLuid.LowPart) {
                debugPrivilegePresent = 1;
        }

        // SE_TCB_NAME check
        if (currLuid.HighPart == tcbPrivLuid.HighPart &&
            currLuid.LowPart == tcbPrivLuid.LowPart) {
                tcbPrivilegePresent = 1;
        }

        // SE_ASSIGNPRIMARYTOKEN_NAME check
        if (currLuid.HighPart == assignPrimaryTokenPrivLuid.HighPart &&
            currLuid.LowPart == assignPrimaryTokenPrivLuid.LowPart) {
                assignPrimaryTokenPrivilegePresent = 1;
        }
    }

    if (!debugPrivilegePresent)              printf("[-] Error: SE_DEBUG_NAME is not enabled\n");
    if (!tcbPrivilegePresent)                printf("[-] Error: SE_TCB_NAME is not enabled\n");
    if (!assignPrimaryTokenPrivilegePresent) printf("[-] Error: SE_ASSIGNPRIMARYTOKEN_NAME is not enabled\n");

CleanupDebug:
    // Cleanup dynamically allocated variables
    if (hToken)           CloseHandle(hToken);
    if (tokenInformation) free(tokenInformation);

    return debugPrivilegePresent && tcbPrivilegePresent && assignPrimaryTokenPrivilegePresent;
}

void PrintUsage() {
/**
 * Purpose: Displays how to use the binary to stdout
 * @return: void - nothing
*/
    printf("Usage: accesstoken.exe <PID>\nWhere <PID> represents the PID of the process with the access token you want to use\n");
}

int ValidateCmdlineArgs(int argc, char **argv) {
/**
 * Purpose: Determines if the binary was called correctly, displays usage if not,
 *          and converts the first parameter to a DWORD
 * @return: DWORWD - If the command line arguments pass validation, the return
 *          value is the PID of the process holding the access token to impersonate.
 *          Otherwise, the return value is -1
*/

    // Make sure the number of arguments is correct
    if (argc != 2) {
        PrintUsage();
        return -1;
    }

    // Convert the first parameter (PID) to a number instead of a string
    char *endptr;
    _set_errno(0);
    int targetProcId = (int)strtoul(argv[1], &endptr, 10);
    if (errno != 0) {
        perror("[-] Error converting PID to int");
        PrintUsage();
        return -1;
    }

    // Bounds check
    if (targetProcId < 1) {
        printf("[-] Error: PID must be larger than 0\n");
        PrintUsage();
        return -1;
    }

    return targetProcId;
}

int main(int argc, char **argv) {

    DWORD targetProcId;         // The ID of the process with the access token to impersonate
    HANDLE hProcess    = NULL;  // Handle to the process with the access token to impersonate
    HANDLE hToken      = NULL;  // Access token to impersonate
    HANDLE hNewToken   = NULL;  // Duplicated access token
    wchar_t *pathToCmd = NULL;  // Full quoted path to cmd.exe

    // Validate the command line arguments
    targetProcId = (DWORD)ValidateCmdlineArgs(argc, argv);
    if (targetProcId == -1) exit(1);

    // Debug privileges (SeDebugPrivilge) are required to open a process owned
    // by another user and get an access token from another user
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken#remarks
    // SE_TCB_NAME and SE_ASSIGNPRIMARYTOKEN_NAME are required to launch a process as another user using an access token
    // https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
    if (!PrivilegesPresent()) {
        printf("[-] Error: The correct privileges are not assigned to the current user. These are prerequisites to creating a process as another user. Try running as SYSTEM\n");
        goto CleanupMain;
    }

    // Open the target process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetProcId);
    if (!hProcess) {
        printf("[-] Error opening PID %d. GetLastError() returned: %d\n", targetProcId, GetLastError());
        goto CleanupMain;
    }
    
    // Get the access token from the target process. These privileges are required in order to use
    // the access token in a call to CreateProcessAsUser: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera#parameters
    if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        printf("[-] Error retrieving process token for PID %d. GetLastError() returned: %d\n", targetProcId, GetLastError());
        goto CleanupMain;
    }

    // Dupliate the token. After some testing, TOKEN_ALL_ACCESS was shown to be required
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &hNewToken)) {
        printf("[-] Error duplicating process token. GetLastError() returned: %d\n", GetLastError());
        goto CleanupMain;
    }

    // Must specify full path to cmd: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera#parameters
    wchar_t systemDirectory[SYSTEM_DIRECTORY_SIZE];
    if (!GetSystemDirectoryW((LPWSTR)systemDirectory, SYSTEM_DIRECTORY_SIZE)) {
        printf("[-] Error finding the system directory. GetLastError() returned: %d\n", GetLastError());
        goto CleanupMain;
    }

    // Add quotes to the path and add cmd.exe
    size_t cmdQuotesAndBackslashLength = wcsnlen_s(L"\\\"cmd.exe\"", 10);
    size_t systemDirectoryLength = wcsnlen_s(systemDirectory, SYSTEM_DIRECTORY_SIZE);
    size_t totalPathLength = cmdQuotesAndBackslashLength + systemDirectoryLength + 1;  // Add 1 for null term
    pathToCmd = (wchar_t *)calloc(totalPathLength, sizeof(wchar_t));
    wcsncat_s(pathToCmd, totalPathLength, L"\"", 1);
    wcsncat_s(pathToCmd, totalPathLength, systemDirectory, systemDirectoryLength);
    wcsncat_s(pathToCmd, totalPathLength, L"\\cmd.exe\"", 9);

    PROCESS_INFORMATION processInformation;
    STARTUPINFOW startInfo;
    ZeroMemory(&startInfo, sizeof(STARTUPINFO));
    startInfo.cb = sizeof(STARTUPINFO);
    if (!CreateProcessAsUserW(hNewToken, NULL, pathToCmd, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &startInfo, &processInformation)) {
        printf("[-] Error creating the process as the impersonated user. GetLastError() returned: %d\n", GetLastError());
        goto CleanupMain;
    }

    printf("[+] Successfully created process as another user!\n\n");

    // Wait for child process to exit
    if (processInformation.hProcess != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(processInformation.hProcess, INFINITE);
        CloseHandle(processInformation.hProcess);
    }
    if (processInformation.hThread != INVALID_HANDLE_VALUE) CloseHandle(processInformation.hThread);

CleanupMain:
    // Close process and token handles
    if (hProcess)  CloseHandle(hProcess);
    if (hToken)    CloseHandle(hToken);
    if (hNewToken) CloseHandle(hNewToken);
    if (pathToCmd) free(pathToCmd);

    return 0;
}
