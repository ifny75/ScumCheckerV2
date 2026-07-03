#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "ScannerShared.h"

#include <Windows.h>
#include <Shlwapi.h>
#include <WinTrust.h>
#include <Softpub.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

namespace {

std::string NarrowLower(std::wstring w) {
    std::transform(w.begin(), w.end(), w.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    std::string s;
    s.reserve(w.size());
    for (wchar_t c : w) {
        s.push_back(static_cast<char>(c <= 0x7F ? c : '?'));
    }
    return s;
}

std::wstring WidenAscii(const std::string& s) {
    std::wstring w;
    w.reserve(s.size());
    for (unsigned char c : s) {
        w.push_back(static_cast<wchar_t>(c));
    }
    return w;
}

std::vector<std::wstring> ParseJsonStringArray(const std::string& json, const std::string& key) {
    std::vector<std::wstring> out;
    const std::string lookup = "\"" + key + "\"";
    size_t pos = json.find(lookup);
    if (pos == std::string::npos) return out;

    pos = json.find('[', pos);
    if (pos == std::string::npos) return out;

    size_t i = pos + 1;
    while (i < json.size()) {
        while (i < json.size() && std::isspace(static_cast<unsigned char>(json[i]))) ++i;
        if (i >= json.size() || json[i] == ']') break;

        if (json[i] == '"') {
            ++i;
            std::string token;
            token.reserve(96);
            while (i < json.size()) {
                char ch = json[i++];
                if (ch == '\\' && i < json.size()) {
                    char n = json[i++];
                    switch (n) {
                    case '\\': token.push_back('\\'); break;
                    case '"': token.push_back('"'); break;
                    case 'n': token.push_back('\n'); break;
                    case 'r': token.push_back('\r'); break;
                    case 't': token.push_back('\t'); break;
                    default: token.push_back(n); break;
                    }
                    continue;
                }
                if (ch == '"') break;
                token.push_back(ch);
            }
            if (!token.empty()) {
                auto w = WidenAscii(token);
                std::transform(w.begin(), w.end(), w.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
                out.push_back(std::move(w));
            }
        }

        while (i < json.size() && json[i] != ',' && json[i] != ']') ++i;
        if (i < json.size() && json[i] == ',') ++i;
    }

    return out;
}

} // namespace

namespace ns {

std::wstring ToLowerCopy(const std::wstring& value) {
    std::wstring out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(towlower(c));
    });
    return out;
}

void WriteBounded(wchar_t* out, size_t outCount, const std::wstring& text) {
    if (!out || outCount == 0) return;
    wcsncpy_s(out, outCount, text.c_str(), _TRUNCATE);
}

std::wstring Basename(const std::wstring& path) {
    const auto pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return path;
    return path.substr(pos + 1);
}

bool ContainsAnyNeedle(const std::wstring& value, const std::vector<std::wstring>& needles) {
    for (const auto& needle : needles) {
        if (!needle.empty() && value.find(needle) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

void PushFinding(
    std::vector<NsFinding>& findings,
    const std::wstring& category,
    const std::wstring& title,
    const std::wstring& reason,
    const std::wstring& details,
    const std::wstring& evidence,
    int severity,
    int score) {
    NsFinding f{};
    WriteBounded(f.category, std::size(f.category), category);
    WriteBounded(f.title, std::size(f.title), title);
    WriteBounded(f.reason, std::size(f.reason), reason);
    WriteBounded(f.details, std::size(f.details), details);
    WriteBounded(f.evidence_path, std::size(f.evidence_path), evidence);
    f.severity = severity;
    f.score = score;
    findings.push_back(f);
}

bool VerifyFileSignature(const std::wstring& path) {
    if (path.empty() || !PathFileExistsW(path.c_str())) {
        return false;
    }

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    LONG status = WinVerifyTrust(nullptr, &policyGuid, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &trustData);

    return status == ERROR_SUCCESS;
}

SignerInfo GetFileSignerInfo(const std::wstring& path) {
    SignerInfo info;
    if (path.empty() || !PathFileExistsW(path.c_str())) {
        return info;
    }

    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;

    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &encoding, &contentType, &formatType,
            &hStore, &hMsg, nullptr)) {
        return info; // unsigned / no embedded PKCS7
    }

    DWORD certInfoSize = 0;
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, nullptr, &certInfoSize) && certInfoSize) {
        std::vector<BYTE> buf(certInfoSize);
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, buf.data(), &certInfoSize)) {
            auto* ci = reinterpret_cast<PCERT_INFO>(buf.data());
            PCCERT_CONTEXT found = CertFindCertificateInStore(
                hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, ci, nullptr);
            if (found) {
                info.present = true;

                wchar_t name[256]{};
                CertGetNameStringW(found, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                   name, static_cast<DWORD>(std::size(name)));
                info.subject = name;

                // SerialNumber blob is little-endian; print in display (big-endian) order.
                const CRYPT_INTEGER_BLOB& sn = found->pCertInfo->SerialNumber;
                std::wstringstream ss;
                ss << std::hex << std::uppercase << std::setfill(L'0');
                for (int i = static_cast<int>(sn.cbData) - 1; i >= 0; --i) {
                    ss << std::setw(2) << static_cast<unsigned>(sn.pbData[i]);
                }
                info.serial = ss.str();

                BYTE hash[20]{};
                DWORD hashLen = sizeof(hash);
                if (CertGetCertificateContextProperty(found, CERT_SHA1_HASH_PROP_ID, hash, &hashLen)) {
                    std::wstringstream hs;
                    hs << std::hex << std::uppercase << std::setfill(L'0');
                    for (DWORD i = 0; i < hashLen; ++i) {
                        hs << std::setw(2) << static_cast<unsigned>(hash[i]);
                    }
                    info.sha1Thumbprint = hs.str();
                }

                CertFreeCertificateContext(found);
            }
        }
    }

    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);
    return info;
}

std::wstring MatchKnownLeakedSigner(const SignerInfo& info) {
    if (!info.present) return L"";

    // Known leaked / abused code-signing certificates. Extend this table as new
    // leaks surface; match by serial primarily, thumbprint as a secondary key.
    struct LeakedCert {
        const wchar_t* serial;     // uppercase hex, leading zeros optional
        const wchar_t* thumbprint; // uppercase SHA-1, or L"" if not pinned
        const wchar_t* label;
    };
    static const LeakedCert kLeaked[] = {
        // NVIDIA certs leaked in the 2022 LAPSUS$ breach — widely reused to sign
        // malicious / mapped kernel drivers (signed via system-clock rollback).
        {L"43BB437D609866286DD839E1D00309F5",
         L"579AEC4489A2CA8A2A09DF5DC0323634BD8B16B7",
         L"NVIDIA Corporation (leaked 2022, expired 2014)"},
        {L"14781BC862E8DC503A559346F5DCC518",
         L"",
         L"NVIDIA Corporation (leaked 2022)"},
    };

    auto normalize = [](std::wstring s) {
        s = ToLowerCopy(s);
        size_t i = 0;
        while (i + 1 < s.size() && s[i] == L'0') ++i; // strip leading zero padding
        return s.substr(i);
    };

    const std::wstring serial = normalize(info.serial);
    const std::wstring thumb = ToLowerCopy(info.sha1Thumbprint);

    for (const auto& c : kLeaked) {
        if (!serial.empty() && serial == normalize(c.serial)) {
            return c.label;
        }
        if (c.thumbprint[0] != L'\0' && !thumb.empty() && thumb == ToLowerCopy(c.thumbprint)) {
            return c.label;
        }
    }
    return L"";
}

bool IsUserSpacePath(const std::wstring& pathLower) {
    return pathLower.find(L"\\users\\") != std::wstring::npos ||
           pathLower.find(L"\\appdata\\") != std::wstring::npos ||
           pathLower.find(L"\\temp\\") != std::wstring::npos;
}

bool IsTempPath(const std::wstring& pathLower) {
    return pathLower.find(L"\\temp\\") != std::wstring::npos ||
           pathLower.find(L"\\tmp\\") != std::wstring::npos;
}

std::wstring TrimQuotesAndArgs(const std::wstring& src) {
    std::wstring v = src;
    while (!v.empty() && iswspace(v.front())) v.erase(v.begin());
    while (!v.empty() && iswspace(v.back())) v.pop_back();
    if (v.empty()) return v;

    if (v.front() == L'"') {
        const auto pos = v.find(L'"', 1);
        if (pos != std::wstring::npos) {
            return v.substr(1, pos - 1);
        }
    }

    const auto space = v.find(L' ');
    if (space != std::wstring::npos) {
        v = v.substr(0, space);
    }
    return v;
}

std::optional<std::wstring> QueryStringValue(HKEY hKey, const wchar_t* valueName) {
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(hKey, valueName, nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return std::nullopt;
    }
    if (size == 0) return std::nullopt;

    std::wstring value;
    value.resize(size / sizeof(wchar_t));
    if (RegQueryValueExW(hKey, valueName, nullptr, nullptr, reinterpret_cast<LPBYTE>(value.data()), &size) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    if (!value.empty() && value.back() == L'\0') value.pop_back();
    return value;
}

std::wstring ExpandEnvironment(const std::wstring& src) {
    if (src.empty()) return src;
    wchar_t expanded[4096]{};
    const DWORD n = ExpandEnvironmentStringsW(src.c_str(), expanded, static_cast<DWORD>(std::size(expanded)));
    if (n == 0 || n >= std::size(expanded)) {
        return src;
    }
    return std::wstring(expanded);
}

bool PathExistsFile(const std::wstring& path) {
    return !path.empty() && PathFileExistsW(path.c_str());
}

std::wstring GetModuleDirectory() {
    HMODULE mod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&GetModuleDirectory),
                            &mod)) {
        return L".";
    }

    wchar_t path[MAX_PATH]{};
    DWORD n = GetModuleFileNameW(mod, path, static_cast<DWORD>(std::size(path)));
    if (n == 0 || n >= std::size(path)) return L".";

    std::filesystem::path p(path);
    return p.parent_path().wstring();
}

std::wstring ComputeSha256Hex(const std::wstring& path, size_t maxBytesToRead) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return L"";
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    PUCHAR hashObject = nullptr;
    PUCHAR hashValue = nullptr;

    DWORD cbData = 0;
    DWORD cbHashObject = 0;
    DWORD cbHash = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&cbHashObject), sizeof(cbHashObject), &cbData, 0) < 0 ||
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&cbHash), sizeof(cbHash), &cbData, 0) < 0) {
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return L"";
    }

    hashObject = static_cast<PUCHAR>(HeapAlloc(GetProcessHeap(), 0, cbHashObject));
    hashValue = static_cast<PUCHAR>(HeapAlloc(GetProcessHeap(), 0, cbHash));
    if (!hashObject || !hashValue || BCryptCreateHash(hAlg, &hHash, hashObject, cbHashObject, nullptr, 0, 0) < 0) {
        if (hashObject) HeapFree(GetProcessHeap(), 0, hashObject);
        if (hashValue) HeapFree(GetProcessHeap(), 0, hashValue);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return L"";
    }

    std::array<unsigned char, 64 * 1024> buffer{};
    ULONGLONG totalRead = 0;
    DWORD readBytes = 0;
    while (ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &readBytes, nullptr) && readBytes > 0) {
        if (maxBytesToRead > 0 && totalRead + readBytes > maxBytesToRead) {
            readBytes = static_cast<DWORD>(maxBytesToRead - totalRead);
        }

        if (readBytes == 0) break;
        if (BCryptHashData(hHash, buffer.data(), readBytes, 0) < 0) {
            break;
        }

        totalRead += readBytes;
        if (maxBytesToRead > 0 && totalRead >= maxBytesToRead) {
            break;
        }
    }

    bool ok = BCryptFinishHash(hHash, hashValue, cbHash, 0) >= 0;

    std::wstring hex;
    if (ok) {
        std::wstringstream ss;
        ss << std::hex << std::setfill(L'0');
        for (DWORD i = 0; i < cbHash; ++i) {
            ss << std::setw(2) << static_cast<unsigned int>(hashValue[i]);
        }
        hex = ss.str();
    }

    BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(), 0, hashObject);
    HeapFree(GetProcessHeap(), 0, hashValue);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    return hex;
}

RuleSet LoadRulesFromJson(const std::wstring& filePath) {
    RuleSet rules;

    rules.strings = { L"cheat", L"inject", L"esp", L"wallhack", L"aimbot", L"trigger", L"spoof", L"mapper" };
    rules.paths = { L"\\temp\\", L"\\appdata\\", L"\\local\\temp\\" };

    std::ifstream in(std::filesystem::path(filePath), std::ios::in | std::ios::binary);
    if (!in) {
        return rules;
    }

    std::string json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    auto parsedStrings = ParseJsonStringArray(json, "strings");
    auto parsedPaths = ParseJsonStringArray(json, "paths");
    auto parsedHashes = ParseJsonStringArray(json, "hashes");

    if (!parsedStrings.empty()) rules.strings = std::move(parsedStrings);
    if (!parsedPaths.empty()) rules.paths = std::move(parsedPaths);
    rules.hashes = std::move(parsedHashes);

    return rules;
}

} // namespace ns
