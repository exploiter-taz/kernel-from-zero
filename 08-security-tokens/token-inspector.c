/*
 * Token inspector: privileges, integrity level, and group SIDs.
 *
 * Compile:  cl /W4 /O2 token-inspector.c advapi32.lib
 */

#include <windows.h>
#include <stdio.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

void DumpPrivileges(void)
{
    printf("--- Privileges ---\n\n");

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed: %u\n\n", GetLastError());
        return;
    }

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed);
    TOKEN_PRIVILEGES *privs = (TOKEN_PRIVILEGES *)malloc(needed);
    if (!privs) { CloseHandle(hToken); return; }

    if (!GetTokenInformation(hToken, TokenPrivileges, privs, needed, &needed)) {
        printf("[-] GetTokenInformation failed: %u\n\n", GetLastError());
        free(privs); CloseHandle(hToken); return;
    }

    printf("%-40s  %s\n", "Privilege", "State");
    printf("%-40s  %s\n", "---------", "-----");

    for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
        char name[256] = {0};
        DWORD nameLen = sizeof(name);
        LookupPrivilegeNameA(NULL, &privs->Privileges[i].Luid, name, &nameLen);

        DWORD attrs = privs->Privileges[i].Attributes;
        const char *state;
        if (attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
            state = "Enabled (default)";
        else if (attrs & SE_PRIVILEGE_ENABLED)
            state = "Enabled";
        else
            state = "Disabled";

        printf("%-40s  %s\n", name, state);
    }

    printf("\nTotal: %u privileges\n", privs->PrivilegeCount);

    int hasDebug = 0;
    for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
        char name[64] = {0};
        DWORD nameLen = sizeof(name);
        LookupPrivilegeNameA(NULL, &privs->Privileges[i].Luid, name, &nameLen);
        if (strcmp(name, "SeDebugPrivilege") == 0) {
            hasDebug = 1;
            break;
        }
    }

    printf("\nSeDebugPrivilege: %s\n\n", hasDebug ? "PRESENT" : "NOT PRESENT");
    free(privs);
    CloseHandle(hToken);
}

void DumpIntegrityLevel(void)
{
    printf("--- Integrity level ---\n\n");

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed\n\n");
        return;
    }

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &needed);
    TOKEN_MANDATORY_LABEL *label = (TOKEN_MANDATORY_LABEL *)malloc(needed);
    if (!label) { CloseHandle(hToken); return; }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, label, needed, &needed)) {
        printf("[-] GetTokenInformation failed\n\n");
        free(label); CloseHandle(hToken); return;
    }

    DWORD il = *GetSidSubAuthority(label->Label.Sid,
        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(label->Label.Sid) - 1));

    const char *ilName;
    switch (il) {
    case 0x0000: ilName = "Untrusted (0x0000)"; break;
    case 0x1000: ilName = "Low (0x1000)"; break;
    case 0x2000: ilName = "Medium (0x2000)"; break;
    case 0x3000: ilName = "Medium-High (0x3000)"; break;
    case 0x4000: ilName = "High (0x4000)"; break;
    case 0x5000: ilName = "System (0x5000)"; break;
    default:     ilName = "Unknown"; break;
    }

    printf("Integrity Level: %s\n\n", ilName);
    free(label);
    CloseHandle(hToken);
}

void DumpGroups(void)
{
    printf("--- Groups ---\n\n");

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed\n\n");
        return;
    }

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &needed);
    TOKEN_GROUPS *groups = (TOKEN_GROUPS *)malloc(needed);
    if (!groups) { CloseHandle(hToken); return; }

    if (!GetTokenInformation(hToken, TokenGroups, groups, needed, &needed)) {
        printf("[-] GetTokenInformation failed\n\n");
        free(groups); CloseHandle(hToken); return;
    }

    printf("%-50s  %s\n", "Group SID", "Attributes");
    printf("%-50s  %s\n", "---------", "----------");

    for (DWORD i = 0; i < groups->GroupCount && i < 20; i++) {
        char *sidStr = NULL;
        ConvertSidToStringSidA(groups->Groups[i].Sid, &sidStr);

        DWORD attrs = groups->Groups[i].Attributes;
        char attrStr[128] = {0};
        if (attrs & SE_GROUP_ENABLED) strcat_s(attrStr, sizeof(attrStr), "Enabled ");
        if (attrs & SE_GROUP_MANDATORY) strcat_s(attrStr, sizeof(attrStr), "Mandatory ");
        if (attrs & SE_GROUP_INTEGRITY) strcat_s(attrStr, sizeof(attrStr), "Integrity ");
        if (attrs & SE_GROUP_OWNER) strcat_s(attrStr, sizeof(attrStr), "Owner ");

        printf("%-50s  %s\n", sidStr ? sidStr : "(null)", attrStr);
        if (sidStr) LocalFree(sidStr);
    }

    printf("\nTotal: %u groups (showing first 20)\n\n", groups->GroupCount);
    free(groups);
    CloseHandle(hToken);
}

int main(void)
{
    printf("=== 08: Security Tokens ===\n\n");

    DumpIntegrityLevel();
    DumpPrivileges();
    DumpGroups();

    printf("=== done ===\n");
    return 0;
}
