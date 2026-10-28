#pragma once

#include "ScannerShared.h"

namespace ns {

struct FileScanLimits {
    int max_depth = 5;
    int max_entries_per_root = 35000;
};

ModuleOutput RunFileScanner(const RuleSet& rules);
// Explicit roots are useful for targeted scans; an empty list uses defaults.
ModuleOutput RunFileScanner(const RuleSet& rules, const std::vector<std::wstring>& selectedRoots,
                            FileScanLimits limits = {});

} // namespace ns
