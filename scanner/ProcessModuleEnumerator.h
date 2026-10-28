#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <limits>
#include <optional>
#include <vector>

namespace ns {

// The module list may grow between calls. Never expose a truncated snapshot to
// callers: missing module ranges could otherwise look like injected code.
template <typename Enumerate>
std::optional<std::vector<HMODULE>> ReadProcessModuleSnapshot(Enumerate&& enumerate) {
    std::vector<HMODULE> modules(256);
    constexpr size_t maxModules = (std::numeric_limits<DWORD>::max)() / sizeof(HMODULE);
    constexpr int maxAttempts = 8;
    for (int attempt = 0; attempt < maxAttempts; ++attempt) {
        DWORD bytesNeeded = 0;
        const auto bytesAvailable = static_cast<DWORD>(modules.size() * sizeof(HMODULE));
        if (!enumerate(modules.data(), bytesAvailable, &bytesNeeded)) return std::nullopt;
        if (bytesNeeded % sizeof(HMODULE) != 0) return std::nullopt;
        const size_t count = bytesNeeded / sizeof(HMODULE);
        if (count <= modules.size()) {
            modules.resize(count);
            return modules;
        }
        if (count > maxModules) return std::nullopt;
        modules.resize(count);
    }
    return std::nullopt;
}

} // namespace ns
