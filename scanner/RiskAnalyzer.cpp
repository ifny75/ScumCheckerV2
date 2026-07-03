#include "RiskAnalyzer.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace {

int ClampSeverity(int s) {
    if (s < NS_SEVERITY_INFO) return NS_SEVERITY_INFO;
    if (s > NS_SEVERITY_HIGH) return NS_SEVERITY_HIGH;
    return s;
}

std::wstring MakeKey(const NsFinding& f) {
    std::wstring k = f.category;
    k += L"|";
    k += f.title;
    k += L"|";
    k += f.evidence_path;
    k += L"|";
    k += f.details;
    return k;
}

} // namespace

namespace ns {

void ApplyRiskAnalysis(std::vector<NsFinding>& findings) {
    if (findings.empty()) return;

    std::unordered_set<std::wstring> seen;
    std::vector<NsFinding> unique;
    unique.reserve(findings.size());

    for (auto& f : findings) {
        const auto key = ns::ToLowerCopy(MakeKey(f));
        if (seen.insert(key).second) {
            unique.push_back(f);
        }
    }

    std::unordered_map<std::wstring, int> perEvidenceCount;
    for (const auto& f : unique) {
        auto ev = ns::ToLowerCopy(f.evidence_path);
        if (!ev.empty()) perEvidenceCount[ev]++;
    }

    for (auto& f : unique) {
        int sev = ClampSeverity(f.severity);
        int score = f.score;

        std::wstring path = ns::ToLowerCopy(f.evidence_path);
        std::wstring title = ns::ToLowerCopy(f.title);
        std::wstring reason = ns::ToLowerCopy(f.reason);

        const bool tempPath = path.find(L"\\temp\\") != std::wstring::npos;
        const bool userPath = tempPath || path.find(L"\\appdata\\") != std::wstring::npos;
        const bool kernelStrong =
            title.find(L"mapper") != std::wstring::npos ||
            title.find(L"vulnerable kernel") != std::wstring::npos ||
            title.find(L"kernel driver") != std::wstring::npos ||
            title.find(L"test-signing") != std::wstring::npos ||
            title.find(L"dse") != std::wstring::npos ||
            title.find(L"leaked certificate") != std::wstring::npos;

        if (userPath && kernelStrong) {
            score += 5;
        }
        if ((title.find(L"unsigned") != std::wstring::npos || reason.find(L"unsigned") != std::wstring::npos) && kernelStrong) {
            score += 5;
        }
        if (kernelStrong) {
            score += 10;
        }

        if (!path.empty()) {
            auto it = perEvidenceCount.find(path);
            if (it != perEvidenceCount.end() && it->second >= 3) {
                score += 8;
                sev = std::max(sev, static_cast<int>(NS_SEVERITY_MEDIUM));
            }
        }

        if (score >= 90 && kernelStrong) sev = NS_SEVERITY_HIGH;
        else if (score >= 72) sev = std::max(sev, static_cast<int>(NS_SEVERITY_MEDIUM));
        else if (score >= 45) sev = std::max(sev, static_cast<int>(NS_SEVERITY_LOW));

        if (!kernelStrong && sev == NS_SEVERITY_HIGH) {
            sev = NS_SEVERITY_MEDIUM;
            score = std::min(score, 78);
        }

        f.score = std::min(score, 100);
        f.severity = ClampSeverity(sev);
    }

    std::sort(unique.begin(), unique.end(), [](const NsFinding& a, const NsFinding& b) {
        if (a.severity != b.severity) return a.severity > b.severity;
        return a.score > b.score;
    });

    findings.swap(unique);
}

} // namespace ns
