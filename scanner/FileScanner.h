#pragma once

#include "ScannerShared.h"

namespace ns {

ModuleOutput RunFileScanner(const RuleSet& rules);
// Explicit roots are useful for targeted scans; an empty list uses defaults.
ModuleOutput RunFileScanner(const RuleSet& rules, const std::vector<std::wstring>& selectedRoots);

} // namespace ns
