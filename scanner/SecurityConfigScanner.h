#pragma once

#include "ScannerShared.h"

namespace ns {

// Inspects the system's protection posture: Secure Boot, kernel code-signing
// enforcement (DSE / test signing), Defender real-time + tamper protection and
// VBS/HVCI. A weakened posture is a precondition for BYOVD / manual-mapped
// cheats, so findings are reported as context-to-high rather than absolute.
ModuleOutput RunSecurityConfigScanner(const RuleSet& rules, bool isAdmin);

} // namespace ns
