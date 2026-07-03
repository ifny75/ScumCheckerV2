#pragma once

#include "ScannerShared.h"

namespace ns {

// Deep system-history inspector backing the "DMA & Network" tab's history view.
// Pulls forensic history that helps reconstruct what hardware was attached and
// what ran on the machine (Layer 2). Categories emitted:
//   "UsbHistory"    : every USB / USBSTOR device ever seen + first/last times
//   "ExecHistory"   : BAM/DAM last-execution records (path + timestamp)
//   "DeviceHistory" : current PnP device inventory by class
//   "NetArp"        : ARP neighbours (other devices on the LAN)
// Severity carries a risk degree; Score 0..100. Read-only registry access;
// some keys (BAM) need admin and degrade gracefully when denied.
ModuleOutput RunSystemHistoryInspector(const RuleSet& rules);

} // namespace ns
