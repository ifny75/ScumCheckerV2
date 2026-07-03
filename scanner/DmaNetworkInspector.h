#pragma once

#include "ScannerShared.h"

namespace ns {

// Inspector backing the "DMA & Network" UI tab (Layer 2 per ARCHITECTURE.md).
// Unlike the scanner modules it lists ALL relevant items (not only suspicious
// ones) so the admin sees the full picture, with a degree encoded per item:
//   - Category "PCIeDevice": every PCIe device + a DMA-risk degree in severity.
//   - Category "NetConn"   : active TCP endpoints + owning process.
//   - Category "NetInfo"   : honesty notes about radar detectability limits.
// Severity field carries the degree (0=Info .. 3=High); Score is 0..100.
ModuleOutput RunDmaNetworkInspector(const RuleSet& rules);

} // namespace ns
