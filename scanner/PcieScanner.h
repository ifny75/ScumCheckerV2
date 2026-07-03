#pragma once

#include "ScannerShared.h"

namespace ns {

// Usermode PCIe device enumeration (Layer 2 per ARCHITECTURE.md).
// Targets DMA attack hardware (FPGA cards such as PCILeech/Squirrel):
//   - flags FPGA/dev-board vendor IDs on the PCIe bus
//   - flags PCIe devices with no bound driver
// Full PCIe config-space inspection (spoof detection via Subsystem/serial) and
// authoritative IOMMU/Kernel-DMA-Protection state require the kernel agent
// (Layer 3); from usermode these are best-effort signals only.
ModuleOutput RunPcieScanner(const RuleSet& rules);

} // namespace ns
