#pragma once

#include "ScannerShared.h"

namespace ns {

// Usermode hypervisor heuristics (Layer 2 per ARCHITECTURE.md).
// Produces RISK SIGNALS only: a present hypervisor is NOT proof of cheating
// (legit VBS / Hyper-V / WSL2 / sandboxes also set the present bit). Severity
// is intentionally conservative; certainty requires the kernel agent (Layer 3).
ModuleOutput RunHypervisorScanner(const RuleSet& rules);

} // namespace ns
