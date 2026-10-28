#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "NativeScannerApi.h"

#include <Windows.h>

#include <optional>
#include <string>
#include <vector>

namespace ns {

struct RuleSet {
    std::vector<std::wstring> strings;
    std::vector<std::wstring> paths;
    std::vector<std::wstring> hashes;
};

struct ModuleOutput {
    int status = NS_MODULE_COMPLETED;
    std::vector<NsFinding> findings;
    int files_checked = 0;
    int services_checked = 0;
    int processes_checked = 0;
    int drivers_checked = 0;
    int registry_values_checked = 0;
    int steam_accounts_checked = 0;
    int errors = 0;
};

std::wstring ToLowerCopy(const std::wstring& value);
void WriteBounded(wchar_t* out, size_t outCount, const std::wstring& text);
std::wstring Basename(const std::wstring& path);
bool ContainsAnyNeedle(const std::wstring& value, const std::vector<std::wstring>& needles);

void PushFinding(
    std::vector<NsFinding>& findings,
    const std::wstring& category,
    const std::wstring& title,
    const std::wstring& reason,
    const std::wstring& details,
    const std::wstring& evidence,
    int severity,
    int score);

bool VerifyFileSignature(const std::wstring& path);

// Authenticode signer of a PE file (the embedded leaf certificate).
struct SignerInfo {
    bool present = false;          // an embedded signature was found and parsed
    std::wstring subject;          // signer common name, e.g. "NVIDIA Corporation"
    std::wstring serial;           // serial number, uppercase hex, display order
    std::wstring sha1Thumbprint;   // certificate SHA-1 thumbprint, uppercase hex
};
SignerInfo GetFileSignerInfo(const std::wstring& path);

// Returns a human label if the signer matches a known leaked/abused code-signing
// certificate (used to sign BYOVD / manual-mapped drivers); empty otherwise.
std::wstring MatchKnownLeakedSigner(const SignerInfo& info);

bool IsUserSpacePath(const std::wstring& pathLower);
bool IsTempPath(const std::wstring& pathLower);
std::wstring TrimQuotesAndArgs(const std::wstring& src);
std::optional<std::wstring> QueryStringValue(HKEY hKey, const wchar_t* valueName);
std::wstring ExpandEnvironment(const std::wstring& src);
bool PathExistsFile(const std::wstring& path);

std::wstring GetModuleDirectory();
// Full-file SHA-256; an empty string indicates an open, read, or hashing error.
std::wstring ComputeSha256Hex(const std::wstring& path);
RuleSet LoadRulesFromJson(const std::wstring& filePath);

} // namespace ns
