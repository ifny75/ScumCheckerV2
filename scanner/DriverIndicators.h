#pragma once
#include "ScannerShared.h"

namespace ns {
std::wstring MatchVulnerableDriverHash(const std::wstring& sha256);
bool IsKnownVulnerableDriverName(const std::wstring& name);
std::wstring NormalizeDriverPath(std::wstring path);
bool ReportVulnerableDriverFile(const std::wstring& path, const wchar_t* category, ModuleOutput& output);
}
