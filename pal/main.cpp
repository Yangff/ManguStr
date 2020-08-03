#include <windows.h>
#include <easyhook.h>
#include <psapi.h>
#include <string>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include "json/json.h"

#define SPECIAL 

// Global Loaded?
#ifdef _DEBUG
#define debugp(...) {fprintf(hf_out, __VA_ARGS__); fflush(hf_out);} while(0);
FILE* hf_out;
#else
#define debugp(...)
#endif
bool gbSystemLoaded = false;


// module locator
HMODULE hMods[1024] = { 0 };

bool EndsWith(const std::wstring & a, const std::wstring & b) {
    if (b.size() > a.size()) return false;
    return _wcsnicmp(a.c_str() + a.size() - b.size(), b.c_str(), b.size()) == 0;
}

HMODULE GetExecutableModule() {
    HANDLE hCurProc = GetCurrentProcess();
    DWORD cbNeeded;
    if (EnumProcessModules(hCurProc, hMods, sizeof(hMods), &cbNeeded))
    {
        for (uint32_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hCurProc, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t)))
            {
                std::wstring wstrModName = szModName;
                if (EndsWith(wstrModName, L".exe")) {
                    CloseHandle(hCurProc);
                    return hMods[i];
                }
            }
        }
    }
    CloseHandle(hCurProc);
    return nullptr;
}

HMODULE hPalOld = nullptr;
HMODULE GetPal_Module() {
    if (hPalOld)
        return hPalOld;
    HANDLE hCurProc = GetCurrentProcess();
    DWORD cbNeeded;
    if (EnumProcessModules(hCurProc, hMods, sizeof(hMods), &cbNeeded))
    {
        for (uint32_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hCurProc, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t)))
            {
                std::wstring wstrModName = szModName;
                if (EndsWith(wstrModName, L"pal_.dll")) {
                    CloseHandle(hCurProc);
                    return hPalOld = hMods[i];
                }
            }
        }
    }
    CloseHandle(hCurProc);
    return hPalOld = LoadLibrary("pal_");
}

// Hooker


typedef int (__cdecl *fpPalFontSetType) (int);
fpPalFontSetType oldPalFontSetType;

extern "C" int __cdecl PalFontSetType(int x) {

    if (!oldPalFontSetType) {
        GetPal_Module();
        if (hPalOld == nullptr) {
            debugp("Still cannot find pal_.dll\n");
        }
        else {
            oldPalFontSetType = (fpPalFontSetType) GetProcAddress(hPalOld, "PalFontSetType");
        }
        if (oldPalFontSetType == nullptr) {
            debugp("oldPalFontSetType == nullptr\n");
        }

        debugp("All up!\n");

    }

    debugp("PalFontSetType(%d)\n",x);
    int y = oldPalFontSetType(0);
    debugp("PalFontSetType(0)=%d OK\n",y);
    return y;
}

void PalModulePatch() {
    // pal hook
    // Here what I patched is a call to GetACP function in pal.dll
    // EasyHook somehow failed to hook this Win32API for no reason
    // It should be easy to find other pal.dll in later version
    // This hook allow Softpal to treat GBK chars as it is, 
    // instead of using SYSTEM encoding.
    GetPal_Module();
    char* patchBegin = (char*)hPalOld + 0x31020;
    const char patch[] = { 0xb8, 0xa8, 0x03,0x00,0x00,0x90 };
    SIZE_T sz;
    bool result = WriteProcessMemory(GetCurrentProcess(), patchBegin, patch, 5, &sz);
    debugp("PalBase = %p, %d bytes written\n", hPalOld, sz);
}

ULONG ACLEntries[1] = { 0 };

HOOK_TRACE_INFO hHookCreateFont = { 0 };
HFONT   WINAPI hookCreateFontA(_In_ int cHeight, _In_ int cWidth, _In_ int cEscapement, _In_ int cOrientation, _In_ int cWeight, _In_ DWORD bItalic,
    _In_ DWORD bUnderline, _In_ DWORD bStrikeOut, _In_ DWORD iCharSet, _In_ DWORD iOutPrecision, _In_ DWORD iClipPrecision,
    _In_ DWORD iQuality, _In_ DWORD iPitchAndFamily, _In_opt_ LPCSTR pszFaceName) {
    if (iCharSet == 0x80 && gbSystemLoaded) {
        // Japanese Font
        debugp("CreateFont hooked\n");
        return CreateFontW(cHeight, cWidth, cEscapement, cOrientation, cWeight, bItalic, bUnderline, bStrikeOut, 0x86, iOutPrecision, iClipPrecision, iQuality, iPitchAndFamily, L"Sarasa Mono SC");
    }
    else
    {
        return CreateFontA(cHeight, cWidth, cEscapement, cOrientation, cWeight, bItalic, bUnderline, bStrikeOut, iCharSet, iOutPrecision, iClipPrecision, iQuality, iPitchAndFamily, pszFaceName);
    }
}

HOOK_TRACE_INFO hHookCreateFontInd = { 0 };
HFONT   WINAPI hookCreateFontIndirectA(_In_ CONST LOGFONTA* lplf) {
    debugp("CreateFont hooked\n");
    return CreateFontIndirectA(lplf);
}

struct LANGANDCODEPAGE {
    WORD wLanguage;
    WORD wCodePage;
} *lpTranslate;


BOOL earlyLoadPoint = false;

char lpRepProductName[] = "ManguSta Discipline";
char lpRepCompany[] = "Papapa";
char lpRepOFN[] = "mangusta.exe";

LANGANDCODEPAGE lcp = { 0x0804 , 0};
HOOK_TRACE_INFO hHookVerQueryValueA = { 0 };
BOOL
APIENTRY
hookVerQueryValueA(
    _In_ LPCVOID pBlock,
    _In_ LPCSTR lpSubBlock,
    _Outptr_result_buffer_(_Inexpressible_("buffer can be PWSTR or DWORD*")) LPVOID* lplpBuffer,
    _Out_ PUINT puLen
) {
    debugp("Request %s\n", lpSubBlock);

    char* buf;
    
    if (strcmp(lpSubBlock, "\\VarFileInfo\\Translation") == 0) {
        *(LANGANDCODEPAGE**)lplpBuffer = &lcp;
        *puLen = sizeof(LANGANDCODEPAGE);
        return true;
    }

    if (strcmp(lpSubBlock, "\\StringFileInfo\\08040000\\ProductName") == 0) {
        *lplpBuffer = (void*) lpRepProductName;
        *puLen = 20;
        return true;
    }

    if (strcmp(lpSubBlock, "\\StringFileInfo\\08040000\\CompanyName") == 0) {
        *lplpBuffer = (void*)lpRepCompany;
        *puLen = 7;
        return true;
    }

    if (strcmp(lpSubBlock, "\\StringFileInfo\\08040000\\OriginalFilename") == 0) {
        *lplpBuffer = lpRepOFN;
        *puLen = 13;
        return true;
    }
    
    return VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen);
}

HOOK_TRACE_INFO hHookGetVolumeInformationA = { 0 };
BOOL
WINAPI
hookGetVolumeInformationA(
    _In_opt_ LPCSTR lpRootPathName,
    _Out_writes_opt_(nVolumeNameSize) LPSTR lpVolumeNameBuffer,
    _In_ DWORD nVolumeNameSize,
    _Out_opt_ LPDWORD lpVolumeSerialNumber,
    _Out_opt_ LPDWORD lpMaximumComponentLength,
    _Out_opt_ LPDWORD lpFileSystemFlags,
    _Out_writes_opt_(nFileSystemNameSize) LPSTR lpFileSystemNameBuffer,
    _In_ DWORD nFileSystemNameSize
) {
    debugp("Hijacked GetVolumeInformationA: %s\n", lpRootPathName);
    if (lpRootPathName[0] == 'e' || lpRootPathName[0] == 'E') {
        strcpy_s(lpVolumeNameBuffer, nVolumeNameSize, "MANGUSTA");
        lpVolumeNameBuffer[8] = 0;
    } else {
        return GetVolumeInformationA(lpRootPathName,
            lpVolumeNameBuffer,
            nVolumeNameSize,
            lpVolumeSerialNumber,
            lpMaximumComponentLength,
            lpFileSystemFlags,
            lpFileSystemNameBuffer,
            nFileSystemNameSize);
    }

}

HOOK_TRACE_INFO hHookGetDriveTypeA = { 0 };
UINT
WINAPI
hookGetDriveTypeA(
    _In_opt_ LPCSTR lpRootPathName
) {
    debugp("Hijacked GetDriveTypeA %s\n", lpRootPathName);
    if (lpRootPathName[0] == 'E' || lpRootPathName[0] == 'e') {
        return 5;
    }
    else {
        return GetDriveTypeA(lpRootPathName);
    }
}

HOOK_TRACE_INFO hHookGetLogicalDrives = { 0 };
DWORD
WINAPI
hookGetLogicalDrives(
    VOID
) {
    debugp("Hijacked GetLogicalDrivers\n");
    return GetLogicalDrives() | (1 << 4);
}
UINT wbuf = 0;
bool get_singlewchar(UINT ch){    
    long sz = MultiByteToWideChar(936, 0, (LPSTR)&ch, strnlen_s((char*)&ch, 2), (LPWSTR)&wbuf, 4);
    return sz != 0;
}

/*
// Enhanced CJK for draw text
HOOK_TRACE_INFO hHookGetGlyphOutlineA = { 0 };
DWORD WINAPI hookGetGlyphOutlineA(_In_ HDC hdc,
    _In_ UINT uChar,
    _In_ UINT fuFormat,
    _Out_ LPGLYPHMETRICS lpgm,
    _In_ DWORD cjBuffer,
    _Out_writes_bytes_opt_(cjBuffer) LPVOID pvBuffer,
    _In_ CONST MAT2* lpmat2
) {
    wbuf = 0;
    if (get_singlewchar(uChar)) {
        debugp("enhance %d to %d\n", uChar, wbuf);
        return GetGlyphOutlineW(hdc, wbuf, fuFormat, lpgm, cjBuffer, pvBuffer, lpmat2);
    } 
}

HOOK_TRACE_INFO hHookGetUserDefaultLCID = { 0 };
LCID
WINAPI
hookGetUserDefaultLCID(void) {
    debugp("GetUserDefaultLCID\n");
    //return 0x804;
    return GetUserDefaultLCID();
}

HOOK_TRACE_INFO hHookGetACP = { 0 };
UINT
WINAPI
hookGetACP(void) {
    debugp("GetACP\n");
    //return 936;
    return GetACP();
}
*/
HOOK_TRACE_INFO hHookGetACP = { 0 };
UINT
WINAPI
hookGetACP(void) {
    return 0x3A8;
}
/*
HOOK_TRACE_INFO hHookGetLocaleInfoW = { 0 };
int
WINAPI
hookGetLocaleInfoW(
    _In_ LCID     Locale,
    _In_ LCTYPE   LCType,
    _Out_writes_opt_(cchData) LPWSTR lpLCData,
    _In_ int      cchData) {
    debugp("GetLocaleInfo %04x %04x\n", Locale, LCType);
    return GetLocaleInfoW(0x804, LCType, lpLCData, cchData);
}


HOOK_TRACE_INFO hHookGetLocaleInfoA = { 0 };
int
WINAPI
hookGetLocaleInfoA(
    _In_ LCID     Locale,
    _In_ LCTYPE   LCType,
    _Out_writes_opt_(cchData) LPSTR lpLCData,
    _In_ int      cchData) {
    debugp("GetLocaleInfo %04x %04x\n", Locale, LCType);
    return GetLocaleInfoA(0x804, LCType, lpLCData, cchData);
}

*/

HOOK_TRACE_INFO hHookGetCPInfo = { 0 };
BOOL
WINAPI
hookGetCPInfo(
    UINT     CodePage,
    LPCPINFO lpCPInfo) {
    //debugp("Hooked GetCPInfo\n");
    return GetCPInfo(0x3A8, lpCPInfo);
}



DWORD hMain = 0;
const unsigned int base = 0x00400000;
const unsigned int offsetRangeCheck = 0x00425d00 - base;
const unsigned int offsetGetChars = 0x00430f00 - base;

const unsigned int offsetGetACP = 0x30fd4;

HOOK_TRACE_INFO hHookRangeCheck = { 0 };
int __cdecl hookRangeCheck(unsigned char* x) {
    //debugp("%d %d\n", *x, *(x+1));
    if (*x >= 0x81 && *x <= 0xFE &&
        (*(x+1) >= 0x40 && *(x+1) <= 0xFE)
    )
        return true;
    return false;
}

typedef char* (*fpGetChars)(int32_t v0, int32_t v1, int32_t v2, uint32_t v3);
fpGetChars hOldGetChars;

HOOK_TRACE_INFO hHookGetChars = { 0 };

bool TryReplace(int id, char* buf);

char* __cdecl hookGetChars(int32_t v0, int32_t v1, int32_t v2, uint32_t v3) {
    char *addr = hOldGetChars(v0,v1,v2,v3);
    
    if ((v2 & 0x10000000) || v3 == 0xFFFFFFF) {
        return addr;
    }
    else 
    {
        int* i = (int*)v0;
        char* ch = (char*)v0 + 4;
        if (*i != 0) {
            if (TryReplace(*i, ch)) {
                //debugp("Replaced\n");
            }
        }
        //debugp("got char %d: %s\n", *i, ch);
    }
    return addr;
}

bool PalPatch() {
    // main hook
    debugp("Base: %p\n", hMain);
    NTSTATUS status = LhInstallHook((void*)(hMain + offsetRangeCheck), hookRangeCheck, nullptr, &hHookRangeCheck);
    debugp("addr of RangeCheck = %p\n", hMain + offsetRangeCheck);
    if (FAILED(status)) {
        debugp("Hook range check failed\n");
        return false;
    }
    status = LhInstallHook((void*)(hMain + offsetGetChars), hookGetChars, nullptr, &hHookGetChars);
    if (FAILED(status)) {
        debugp("Hook get chars failed\n");
        return false;
    }

    debugp("addr of GetChars = %p\n", hMain + offsetGetChars);
    
    hOldGetChars = (fpGetChars)(hMain + offsetGetChars);

    LhSetExclusiveACL(ACLEntries, 0, &hHookRangeCheck);
    LhSetExclusiveACL(ACLEntries, 0, &hHookGetChars);

    return true;
}
#define hookCheck(x) {NTSTATUS s = x; if (FAILED(s)) { debugp(#x" Failed\n"); return false;} }

// translator
std::vector<std::wstring> plantext; // shift_jis
std::vector<std::wstring> translate; // wchar_t
std::vector<bool> hasTrans;

wchar_t* get_wchar(const char *ch, long len, long &new_len)
{
    if (!ch) return nullptr;
    long sz = MultiByteToWideChar(CP_UTF8, 0, ch, len, 0, 0);
    wchar_t* new_buf = new wchar_t[sz + 1];
    sz = MultiByteToWideChar(CP_UTF8, 0, ch, len, new_buf, sz);
    new_buf[sz] = 0;
    new_len = sz;
    return new_buf;
}

bool get_gb(const wchar_t* ch, long len, char* new_buf) {
    if (!ch) return false;
    long sz = WideCharToMultiByte(54936, 0, ch, len, (LPSTR)new_buf, 256, 0, 0);
    if (sz > 256)
        return false;
    new_buf[sz] = 0;
    return true;
}

bool TryReplace(int id, char* buf) {
    if (id >= hasTrans.size())
        return false;
    if (!hasTrans[id])
        return false;
    std::wstring wcsTran = translate[id].c_str();
    //MessageBoxW(0, wcsTran.c_str(), L"Preview", 0);
    return get_gb(wcsTran.c_str(), wcsTran.length(), buf);
}

bool LoadTranslatorFile() {
    FILE* ftrans;
    fopen_s(&ftrans, "TRANS.json", "rb");
    fseek(ftrans, 0, SEEK_END);
    size_t sz = ftell(ftrans);
    char* orgbuf = new char[sz];
    fseek(ftrans, 0, SEEK_SET);
    fread(orgbuf, 1, sz, ftrans);
    fclose(ftrans);
    Json::CharReaderBuilder readerBuilder;
    Json::CharReader* reader = readerBuilder.newCharReader();
    Json::Value root;
    std::wstring wempty;
    Json::String err;
    if (reader->parse(orgbuf, orgbuf + sz, &root, &err)) {
        if (root.isArray()) {
            int szTrans = root.size();
            debugp("%d items in trans file", szTrans);
            for (int i = 0; i < szTrans; i++) {
                Json::Value sub = root[i];
                
                auto str = sub["context"].asString();
                long nsz;
                auto wch = get_wchar(str.c_str(), str.length(), nsz);
                plantext.push_back(wch);
                hasTrans.push_back(true);
                if (!sub.isMember("trans")) {
                    auto tstr = sub["context"].asString();
                    long nsz;
                    auto wch = get_wchar(tstr.c_str(), tstr.length(), nsz);
                    translate.push_back(wch);
                } else {
                    auto tstr = sub["trans"].asString();
                    long nsz;
                    auto wch = get_wchar(tstr.c_str(), tstr.length(), nsz);
                    translate.push_back(wch);
                }
            }
        }
    } else {
        debugp("Failed in jsoncpp");
        debugp(err.c_str());
        return false;
    }
    return true;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH: {
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        
#ifdef _DEBUG
        AllocConsole();

        HANDLE handle_out = GetStdHandle(STD_OUTPUT_HANDLE);

        int hCrt = _open_osfhandle((long)handle_out, _O_TEXT);
        hf_out = _fdopen(hCrt, "w");
        setvbuf(hf_out, NULL, _IONBF, 1);
        debugp("Hello!\n");
#endif        
        AddDllDirectory(L"\\dll");
        if (LoadTranslatorFile()) {
            hMain = (DWORD)GetExecutableModule();
            if (hMain == 0) {
                debugp("Failed Getting executable location!\n");
                break;
            }

            if (!PalPatch()) {
                debugp("Failed Applying Pal!\n");
                break;
            }

            NTSTATUS status = LhInstallHook(
                GetProcAddress(GetModuleHandle("Gdi32"), "CreateFontA"),
                hookCreateFontA,
                nullptr,
                &hHookCreateFont
            );

            status = LhInstallHook(
                GetProcAddress(GetModuleHandle("Gdi32"), "CreateFontIndirectA"),
                hookCreateFontIndirectA,
                nullptr,
                &hHookCreateFontInd
            );

            if (FAILED(status)) {
                debugp("Hook CreateFontA Failed\n");
                break;
            }

            status = LhInstallHook(
                GetProcAddress(GetModuleHandle("version"), "VerQueryValueA"),
                hookVerQueryValueA,
                nullptr,
                &hHookVerQueryValueA
            );


            if (FAILED(status)) {
                debugp("Hook VerQueryValueA Failed\n");
                break;
            }

            status = LhSetExclusiveACL(ACLEntries, 0, &hHookCreateFont);
            status = LhSetExclusiveACL(ACLEntries, 0, &hHookCreateFontInd);

            if (FAILED(status)) {
                debugp("Failed applying ACL on create font\n");
                break;
            }

            status = LhSetExclusiveACL(ACLEntries, 0, &hHookVerQueryValueA);

            if (FAILED(status)) {
                debugp("Failed applying ACL on ver query value\n");
                break;
            }
            
            /*
            status = LhInstallHook(
                GetProcAddress(GetModuleHandle("Gdi32"), "GetGlyphOutlineA"),
                hookGetGlyphOutlineA,
                0,
                &hHookGetGlyphOutlineA
            );
            status = LhSetExclusiveACL(ACLEntries, 0, &hHookGetGlyphOutlineA);

            
            hookCheck(LhInstallHook(
                GetProcAddress(GetModuleHandle("Kernel32"), "GetLocaleInfoA"),
                hookGetLocaleInfoA,
                0,
                &hHookGetLocaleInfoA
            ));
            hookCheck(LhSetExclusiveACL(ACLEntries, 0, &hHookGetLocaleInfoA));
            */
            //debugp("GetACP=%p\n", );
            DWORD addrGetACP = (DWORD)GetProcAddress(GetModuleHandle("kernelbase"), "GetACP");
            const char patch[] = { 0xb8, 0xa8, 0x03,0x00,0x00,0xc3 }; // mov eax,0x03a8; ret;
            DWORD sz = 0;
            WriteProcessMemory(GetCurrentProcess(), (LPVOID)addrGetACP, patch, 5, &sz);
            /*LhInstallHook(
                GetProcAddress(GetModuleHandle("kernelbase"), "GetACP"),
                hookGetACP,
                0,
                &hHookGetACP
            );
            LhSetExclusiveACL(ACLEntries, 0, &hHookGetACP);*/
            /*
            
            LhInstallHook(
                GetProcAddress(GetModuleHandle("kernelbase"), "GetCPInfo"),
                hookGetCPInfo,
                0,
                &hHookGetCPInfo
            );
            LhSetExclusiveACL(ACLEntries, 0, &hHookGetCPInfo);
            */

            // All loaded
            gbSystemLoaded = true;

        } else {
            debugp("Failed when loading translator!\n");
        }
        break;
    }
    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        if (gbSystemLoaded) {
            LhUninstallHook(&hHookCreateFont);
            LhUninstallHook(&hHookRangeCheck);
            LhUninstallHook(&hHookGetChars);
            LhWaitForPendingRemovals();
        }
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}