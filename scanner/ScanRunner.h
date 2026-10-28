#pragma once

#include "NativeScannerApi.h"
#include <vector>

namespace ns {
enum class ScanMode { Full, Steam, History, SecurityConfig, DmaNetwork, Kernel };

// Retains every finding from this scan; no caller-sized buffer or second scan.
int RunScan(ScanMode mode, std::vector<NsFinding>& findings, NsReport& report);
}
