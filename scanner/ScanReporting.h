#pragma once

#include "ScannerShared.h"

namespace ns {

inline void MergeModuleOutput(const wchar_t* name, const ModuleOutput& output,
                              NsReport& report, std::vector<NsFinding>& findings) {
    report.files_checked += output.files_checked;
    report.drivers_checked += output.drivers_checked;
    report.services_checked += output.services_checked;
    report.processes_checked += output.processes_checked;
    report.registry_values_checked += output.registry_values_checked;
    report.steam_accounts_checked += output.steam_accounts_checked;
    report.errors += output.errors;
    const int status = output.status == NS_MODULE_COMPLETED && output.errors > 0
        ? NS_MODULE_PARTIAL : output.status;
    if (report.modules_returned < static_cast<int>(std::size(report.modules))) {
        auto& module = report.modules[report.modules_returned++];
        WriteBounded(module.name, std::size(module.name), name);
        module.status = status;
        module.errors = output.errors;
    } else {
        ++report.errors;
    }
    if ((status != NS_MODULE_COMPLETED || report.errors > 0) && report.status == NS_STATUS_OK) {
        report.status = NS_STATUS_PARTIAL;
    }
    findings.insert(findings.end(), output.findings.begin(), output.findings.end());
}

inline ModuleOutput FailedModule() {
    ModuleOutput output;
    output.status = NS_MODULE_FAILED;
    output.errors = 1;
    return output;
}

} // namespace ns
