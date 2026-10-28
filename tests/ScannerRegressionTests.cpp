#include "FileScanner.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct Fixture {
    std::filesystem::path root = std::filesystem::temp_directory_path() /
        (L"ScumCheckerRegression-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    Fixture() { std::filesystem::create_directories(root / L"nested"); }
    ~Fixture() { std::error_code ec; std::filesystem::remove_all(root, ec); }
};

void TestRepeatedFileScans() {
    Fixture fixture;
    const auto file = fixture.root / L"nested" / L"regression-marker.json";
    std::ofstream(file) << "{}";
    ns::RuleSet rules;
    rules.strings = {L"regression-marker"};
    const std::vector<std::wstring> roots = {fixture.root.wstring(), file.parent_path().wstring()};
    for (int i = 0; i < 2; ++i) {
        const auto result = ns::RunFileScanner(rules, roots);
        Require(result.errors == 0, "File scan failed");
        Require(result.files_checked == 1, "Overlapping roots counted a file twice");
        Require(result.findings.size() == 1, "Repeated scan lost or duplicated an unchanged finding");
    }
    rules.strings.clear();
    Require(ns::RunFileScanner(rules, roots).findings.empty(), "Old rule finding survived rule change");
    rules.strings = {L"regression-marker"};
    Require(ns::RunFileScanner(rules, roots).findings.size() == 1, "Changed rules did not re-evaluate unchanged file");
}
}

int main() {
    try {
        TestRepeatedFileScans();
        std::cout << "Scanner regressions passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 1;
    }
}
