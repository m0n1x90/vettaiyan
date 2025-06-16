#include "Utils.h"

std::wstring GetAssetPath(const std::wstring& assetName) {

    std::wstring cwd = GetExecutableDir();
    return cwd + L"\\" + assetName;

}

std::wstring GetExecutableDir() {

    wchar_t path[MAX_PATH];
    DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);

    if (length == 0 || length == MAX_PATH) {
        std::wcerr << L"[-] GetModuleFileNameW() error" << std::endl;
        return L"";
    }

    std::wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? fullPath.substr(0, pos) : L"";

}

std::wstring Utf8ToWide(const char* utf8Str) {

    if (!utf8Str) return L"";

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8Str, -1, nullptr, 0);
    std::wstring result(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8Str, -1, &result[0], size_needed);
    result.pop_back();
    return result;

}

void LoadPathIntoBuffer(std::wstring assetName, wchar_t* buffer, size_t bufferSize) {

    std::wstring scannerPath = GetAssetPath(assetName);

    if (!scannerPath.empty()) {
        if (scannerPath.length() < bufferSize) {
            wcscpy_s(buffer, bufferSize, scannerPath.c_str());
            std::wcout << L"Scanner path loaded: " << buffer << std::endl;
        }
        else {
            std::wcerr << L"Buffer too small to hold scanner path!" << std::endl;
        }
    }
    else {
        std::wcerr << L"Failed to retrieve scanner path!" << std::endl;
    }

}

std::wstring UrlEncode(const std::wstring& value) {

    std::wostringstream escaped;
    escaped.fill(L'0');
    escaped << std::hex;

    for (wchar_t c : value)
    {
        if (iswalnum(c) || c == L'-' || c == L'_' || c == L'.' || c == L'~')
        {
            escaped << c;
        }
        else
        {
            escaped << L'%' << std::uppercase << std::setw(2) << int((unsigned char)c);
        }
    }

    return escaped.str();

}

std::wstring ComputeSHA256(const std::wstring& filePath) {

    std::wstring hashString = L"";

    HANDLE hFile = CreateFileW(
        filePath.c_str(), 
        GENERIC_READ, 
        FILE_SHARE_READ, 
        NULL,
        OPEN_EXISTING, 
        FILE_FLAG_SEQUENTIAL_SCAN, 
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) return L"";

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    BYTE buffer[4096];
    DWORD bytesRead;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {

        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
            CryptHashData(hHash, buffer, bytesRead, 0);
        }

        BYTE hash[32];
        DWORD hashLen = sizeof(hash);
        if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
            for (DWORD i = 0; i < hashLen; ++i) {
                wchar_t byteStr[3];
                swprintf(byteStr, 3, L"%02x", hash[i]);
                hashString += byteStr;
            }
        }

        CryptDestroyHash(hHash);
    }

    if (hProv) CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return hashString;

}

std::wstring GetMimeType(const std::wstring& filePath) {

    std::string narrowPath(filePath.begin(), filePath.end());

    std::wstring wideMagicPath = GetAssetPath(L"magic.mgc");
    std::string magicDbPath(wideMagicPath.begin(), wideMagicPath.end());

    magic_t magic = magic_open(MAGIC_MIME_TYPE);
    if (!magic) return L"Unknown";

    if (magic_load(magic, magicDbPath.c_str()) != 0) {
        magic_close(magic);
        return L"Unknown";
    }

    const char* mime = magic_file(magic, narrowPath.c_str());
    std::wstring result = mime ? std::wstring(mime, mime + strlen(mime)) : L"Unknown";

    magic_close(magic);
    return result;

}