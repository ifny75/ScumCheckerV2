#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <Shellapi.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <WinHttp.h>
#include <WebView2.h>
#include <wrl.h>

#include "NativeScannerApi.h"
#include "resource.h"
#include "web_manifest.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#pragma comment(lib, "winhttp.lib")

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;

namespace {

constexpr wchar_t kWindowClass[] = L"ScumCheckerV2Window";
constexpr UINT WM_SCAN_RESULT = WM_APP + 42;

// Virtual origin for the embedded web UI. Nothing is served from disk; every
// request under this origin is satisfied from RCDATA resources baked into the .exe.
constexpr wchar_t kAppOrigin[] = L"https://scumchecker.app/";

struct AppState {
    HWND hwnd = nullptr;
    std::filesystem::path exeDir;
    ComPtr<ICoreWebView2Environment> environment;
    ComPtr<ICoreWebView2Controller> controller;
    ComPtr<ICoreWebView2> webview;
    std::atomic_bool scanRunning = false;
};

AppState g_app;

std::wstring JsonEscape(std::wstring_view value) {
    std::wstring out;
    out.reserve(value.size() + 16);
    for (wchar_t ch : value) {
        switch (ch) {
        case L'\\': out += L"\\\\"; break;
        case L'"': out += L"\\\""; break;
        case L'\b': out += L"\\b"; break;
        case L'\f': out += L"\\f"; break;
        case L'\n': out += L"\\n"; break;
        case L'\r': out += L"\\r"; break;
        case L'\t': out += L"\\t"; break;
        default:
            if (ch < 0x20) {
                wchar_t buf[7]{};
                swprintf_s(buf, L"\\u%04x", static_cast<unsigned int>(ch));
                out += buf;
            } else {
                out += ch;
            }
            break;
        }
    }
    return out;
}

std::wstring JsonString(std::wstring_view value) {
    return L"\"" + JsonEscape(value) + L"\"";
}

std::wstring SeverityName(int severity) {
    switch (severity) {
    case NS_SEVERITY_HIGH: return L"High";
    case NS_SEVERITY_MEDIUM: return L"Medium";
    case NS_SEVERITY_LOW: return L"Low";
    default: return L"Info";
    }
}

std::filesystem::path GetExeDirectory() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    return std::filesystem::path(path).parent_path();
}

std::wstring FindJsonValue(const std::wstring& json, const std::wstring& key) {
    const std::wstring needle = L"\"" + key + L"\"";
    size_t pos = json.find(needle);
    if (pos == std::wstring::npos) return L"";
    pos = json.find(L':', pos + needle.size());
    if (pos == std::wstring::npos) return L"";
    pos = json.find(L'"', pos + 1);
    if (pos == std::wstring::npos) return L"";

    std::wstring value;
    for (++pos; pos < json.size(); ++pos) {
        const wchar_t ch = json[pos];
        if (ch == L'\\' && pos + 1 < json.size()) {
            value.push_back(json[++pos]);
            continue;
        }
        if (ch == L'"') break;
        value.push_back(ch);
    }
    return value;
}

std::wstring HtmlDecodeLite(std::wstring value) {
    struct Pair { const wchar_t* from; const wchar_t* to; };
    const Pair pairs[] = {
        {L"&amp;", L"&"}, {L"&quot;", L"\""}, {L"&#39;", L"'"},
        {L"&lt;", L"<"}, {L"&gt;", L">"}
    };
    for (const auto& pair : pairs) {
        size_t pos = 0;
        while ((pos = value.find(pair.from, pos)) != std::wstring::npos) {
            value.replace(pos, wcslen(pair.from), pair.to);
            pos += wcslen(pair.to);
        }
    }
    return value;
}

std::wstring ExtractBetween(const std::wstring& text, const std::wstring& left, const std::wstring& right) {
    const auto l = text.find(left);
    if (l == std::wstring::npos) return L"";
    const auto start = l + left.size();
    const auto r = text.find(right, start);
    if (r == std::wstring::npos) return L"";
    return text.substr(start, r - start);
}

int ExtractIntAfter(const std::wstring& text, const std::wstring& marker) {
    const auto pos = text.find(marker);
    if (pos == std::wstring::npos) return 0;
    size_t i = pos + marker.size();
    while (i < text.size() && !iswdigit(text[i])) ++i;
    int value = 0;
    while (i < text.size() && iswdigit(text[i])) {
        value = value * 10 + (text[i] - L'0');
        ++i;
    }
    return value;
}

int ExtractIntBefore(const std::wstring& text, const std::wstring& marker) {
    const auto pos = text.find(marker);
    if (pos == std::wstring::npos || pos == 0) return 0;
    size_t end = pos;
    while (end > 0 && !iswdigit(text[end - 1])) --end;
    size_t start = end;
    while (start > 0 && iswdigit(text[start - 1])) --start;
    if (start == end) return 0;
    int value = 0;
    for (size_t i = start; i < end; ++i) {
        value = value * 10 + (text[i] - L'0');
    }
    return value;
}

std::wstring HttpGet(const std::wstring& host, const std::wstring& path) {
    HINTERNET session = WinHttpOpen(
        L"ScumCheckerV2/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!session) return L"";

    HINTERNET connect = WinHttpConnect(session, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return L"";
    }

    HINTERNET request = WinHttpOpenRequest(
        connect,
        L"GET",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return L"";
    }

    DWORD timeout = 9000;
    WinHttpSetOption(request, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(request, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    std::string bytes;
    if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(request, nullptr)) {
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
            std::string chunk;
            chunk.resize(available);
            DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read) || read == 0) break;
            chunk.resize(read);
            bytes += chunk;
            if (bytes.size() > 2 * 1024 * 1024) break;
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    if (bytes.empty()) return L"";
    const int needed = MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (needed <= 0) return L"";
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), out.data(), needed);
    return out;
}

void FetchSteamProfileAsync(std::wstring steamId) {
    std::thread([steamId = std::move(steamId)]() {
        std::wstring persona = steamId;
        std::wstring avatar;
        bool unknown = true;
        bool vacBanned = false;
        int vacBans = 0;
        int gameBans = 0;
        int days = -1;

        const auto xml = HttpGet(L"steamcommunity.com", L"/profiles/" + steamId + L"/?xml=1");
        if (!xml.empty()) {
            unknown = false;
            persona = HtmlDecodeLite(ExtractBetween(xml, L"<steamID><![CDATA[", L"]]></steamID>"));
            if (persona.empty()) persona = HtmlDecodeLite(ExtractBetween(xml, L"<steamID>", L"</steamID>"));
            if (persona.empty()) persona = steamId;
            avatar = ExtractBetween(xml, L"<avatarFull><![CDATA[", L"]]></avatarFull>");
            if (avatar.empty()) avatar = ExtractBetween(xml, L"<avatarMedium><![CDATA[", L"]]></avatarMedium>");
            const auto vac = ExtractBetween(xml, L"<vacBanned>", L"</vacBanned>");
            vacBanned = vac == L"1" || vac == L"true";
            vacBans = ExtractIntAfter(xml, L"<numberOfVACBans>");
            gameBans = ExtractIntAfter(xml, L"<numberOfGameBans>");
            const int parsedDays = ExtractIntAfter(xml, L"<daysSinceLastBan>");
            if (parsedDays > 0) days = parsedDays;
        }

        const auto html = HttpGet(L"steamcommunity.com", L"/profiles/" + steamId + L"/?l=english");
        if (!html.empty()) {
            if (avatar.empty()) avatar = HtmlDecodeLite(ExtractBetween(html, L"<meta property=\"og:image\" content=\"", L"\""));
            if (persona == steamId) {
                auto title = HtmlDecodeLite(ExtractBetween(html, L"<span class=\"actual_persona_name\">", L"</span>"));
                if (!title.empty()) persona = title;
            }
            if (gameBans == 0) {
                const int htmlGame = ExtractIntBefore(html, L"game ban");
                if (htmlGame > 0) gameBans = htmlGame;
            }
            if (days < 0) {
                const int htmlDays = ExtractIntAfter(html, L"Days since last ban:");
                if (htmlDays > 0) days = htmlDays;
            }
        }

        auto payload = std::make_unique<std::wstring>(
            L"{\"type\":\"steamProfile\",\"steamId\":" + JsonString(steamId) +
            L",\"unknown\":" + (unknown ? L"true" : L"false") +
            L",\"persona\":" + JsonString(persona) +
            L",\"avatar\":" + JsonString(avatar) +
            L",\"vacBanned\":" + (vacBanned ? L"true" : L"false") +
            L",\"vacBans\":" + std::to_wstring(vacBans) +
            L",\"gameBans\":" + std::to_wstring(gameBans) +
            L",\"daysSinceLastBan\":" + (days >= 0 ? std::to_wstring(days) : L"null") +
            L"}");
        PostMessageW(g_app.hwnd, WM_SCAN_RESULT, 0, reinterpret_cast<LPARAM>(payload.release()));
    }).detach();
}

void RevealPath(const std::wstring& rawPath) {
    if (rawPath.empty()) return;
    std::wstring path = rawPath;
    if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"') {
        path = path.substr(1, path.size() - 2);
    }

    if (!std::filesystem::exists(path)) {
        ShellExecuteW(g_app.hwnd, L"open", L"explorer.exe", nullptr, nullptr, SW_SHOWNORMAL);
        return;
    }

    const std::wstring args = L"/select,\"" + path + L"\"";
    ShellExecuteW(g_app.hwnd, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
}

std::filesystem::path ProfilePath(const std::wstring& profileId) {
    std::wstring safe = profileId;
    safe.erase(std::remove_if(safe.begin(), safe.end(), [](wchar_t ch) {
        return !(iswalnum(ch) || ch == L'-' || ch == L'_');
    }), safe.end());

    if (safe.empty()) safe = L"scum";
    auto path = g_app.exeDir / L"profiles" / (safe + L".json");
    if (!std::filesystem::exists(path)) {
        path = g_app.exeDir / L"profiles" / L"scum.json";
    }
    return path;
}

std::wstring ProfilesJson() {
    return LR"({"type":"profiles","profiles":[)"
        LR"({"id":"scum","name":"SCUM","status":"primary","enabled":true,"note":"Основной профиль чекера"},)"
        LR"({"id":"minecraft","name":"Minecraft","status":"soon","enabled":false,"note":"soon..."},)"
        LR"({"id":"cs","name":"CS","status":"soon","enabled":false,"note":"soon... нет читов для настройки чекера"})"
        LR"(]})";
}

std::wstring FindingToJson(const NsFinding& f) {
    std::wstringstream json;
    json << L"{"
         << L"\"category\":" << JsonString(f.category) << L","
         << L"\"title\":" << JsonString(f.title) << L","
         << L"\"reason\":" << JsonString(f.reason) << L","
         << L"\"details\":" << JsonString(f.details) << L","
         << L"\"evidencePath\":" << JsonString(f.evidence_path) << L","
         << L"\"severity\":" << f.severity << L","
         << L"\"severityName\":" << JsonString(SeverityName(f.severity)) << L","
         << L"\"score\":" << f.score
         << L"}";
    return json.str();
}

std::wstring ScanResultJson(
    const std::wstring& profile,
    const std::wstring& mode,
    int status,
    const NsReport& report,
    const std::vector<NsFinding>& findings) {
    std::wstringstream json;
    json << L"{"
         << L"\"type\":\"scanResult\","
         << L"\"profile\":" << JsonString(profile) << L","
         << L"\"mode\":" << JsonString(mode) << L","
         << L"\"status\":" << status << L","
         << L"\"report\":{"
         << L"\"findingsReturned\":" << report.findings_returned << L","
         << L"\"filesChecked\":" << report.files_checked << L","
         << L"\"driversChecked\":" << report.drivers_checked << L","
         << L"\"servicesChecked\":" << report.services_checked << L","
         << L"\"processesChecked\":" << report.processes_checked << L","
         << L"\"registryValuesChecked\":" << report.registry_values_checked << L","
         << L"\"steamAccountsChecked\":" << report.steam_accounts_checked << L","
         << L"\"errors\":" << report.errors << L","
         << L"\"ranAsAdmin\":" << (report.ran_as_admin ? L"true" : L"false") << L","
         << L"\"elapsedMs\":" << report.elapsed_ms
         << L",\"modules\":[";
    for (int i = 0; i < report.modules_returned; ++i) {
        if (i) json << L",";
        const auto& module = report.modules[i];
        json << L"{\"name\":" << JsonString(module.name)
             << L",\"status\":" << module.status << L",\"errors\":" << module.errors << L"}";
    }
    json << L"]},\"findings\":[";

    for (size_t i = 0; i < findings.size(); ++i) {
        if (i != 0) json << L",";
        json << FindingToJson(findings[i]);
    }
    json << L"]}";
    return json.str();
}

void SendToWeb(const std::wstring& json) {
    if (!g_app.webview) return;
    const std::wstring script = L"window.ScumChecker&&window.ScumChecker.receive(" + json + L");";
    g_app.webview->ExecuteScript(script.c_str(), nullptr);
}

void PostScanError(const std::wstring& profile, const std::wstring& message) {
    auto payload = std::make_unique<std::wstring>(
        L"{\"type\":\"scanError\",\"profile\":" + JsonString(profile) +
        L",\"message\":" + JsonString(message) + L"}");
    PostMessageW(g_app.hwnd, WM_SCAN_RESULT, 0, reinterpret_cast<LPARAM>(payload.release()));
}

void RunScanAsync(std::wstring profile, std::wstring mode) {
    bool expected = false;
    if (!g_app.scanRunning.compare_exchange_strong(expected, true)) {
        SendToWeb(L"{\"type\":\"scanBusy\"}");
        return;
    }

    SendToWeb(L"{\"type\":\"scanStarted\",\"profile\":" + JsonString(profile) +
              L",\"mode\":" + JsonString(mode) + L"}");

    std::thread([profile = std::move(profile), mode = std::move(mode)]() {
        try {
            const auto rulesPath = ProfilePath(profile).wstring();
            Ns_SetRulesPath(rulesPath.c_str());

            constexpr int kCapacity = 4096;
            std::vector<NsFinding> buffer(kCapacity);
            NsReport report{};
            int status = 0;

            if (mode == L"dma") {
                status = Ns_RunDmaNetworkInspect(buffer.data(), static_cast<int>(buffer.size()), &report);
            } else if (mode == L"steam") {
                status = Ns_RunSteamScan(buffer.data(), static_cast<int>(buffer.size()), &report);
            } else if (mode == L"history") {
                status = Ns_RunHistoryScan(buffer.data(), static_cast<int>(buffer.size()), &report);
            } else if (mode == L"seccfg") {
                status = Ns_RunSecurityConfigScan(buffer.data(), static_cast<int>(buffer.size()), &report);
            } else if (mode == L"kernel") {
                status = Ns_RunKernelSysScan(buffer.data(), static_cast<int>(buffer.size()), &report);
            } else {
                status = Ns_RunDriverMemoryScan(buffer.data(), static_cast<int>(buffer.size()), &report);
            }

            const int count = std::clamp(report.findings_returned, 0, static_cast<int>(buffer.size()));
            buffer.resize(static_cast<size_t>(count));

            auto payload = std::make_unique<std::wstring>(ScanResultJson(profile, mode, status, report, buffer));
            PostMessageW(g_app.hwnd, WM_SCAN_RESULT, 0, reinterpret_cast<LPARAM>(payload.release()));
        } catch (const std::exception& ex) {
            std::wstring message(ex.what(), ex.what() + strlen(ex.what()));
            PostScanError(profile, message);
        } catch (...) {
            PostScanError(profile, L"Unknown native scan failure.");
        }
    }).detach();
}

void OpenExternal(const std::wstring& target) {
    if (target.empty()) return;

    std::wstring resolved = target;
    if (target == L"prefetch") {
        wchar_t win[MAX_PATH]{};
        GetWindowsDirectoryW(win, static_cast<UINT>(std::size(win)));
        resolved = std::wstring(win) + L"\\Prefetch";
    } else if (target == L"recent") {
        resolved = L"shell:recent";
    } else if (target == L"appdata") {
        wchar_t path[MAX_PATH]{};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path))) {
            resolved = path;
        }
    } else if (target == L"localappdata") {
        wchar_t path[MAX_PATH]{};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path))) {
            resolved = path;
        }
    } else if (target == L"steam_loginusers") {
        wchar_t pf86[MAX_PATH]{};
        if (GetEnvironmentVariableW(L"ProgramFiles(x86)", pf86, static_cast<DWORD>(std::size(pf86))) > 0) {
            resolved = std::wstring(pf86) + L"\\Steam\\config\\loginusers.vdf";
        }
    } else if (target == L"eventvwr") {
        resolved = L"eventvwr.msc";
    } else if (target == L"downloads") {
        wchar_t path[MAX_PATH]{};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, SHGFP_TYPE_CURRENT, path))) {
            resolved = std::wstring(path) + L"\\Downloads";
        }
    } else if (target == L"desktop") {
        wchar_t path[MAX_PATH]{};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, SHGFP_TYPE_CURRENT, path))) {
            resolved = path;
        }
    } else if (target == L"temp") {
        wchar_t path[MAX_PATH]{};
        if (GetTempPathW(static_cast<DWORD>(std::size(path)), path) > 0) {
            resolved = path;
        }
    } else if (target == L"programdata") {
        wchar_t path[MAX_PATH]{};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path))) {
            resolved = path;
        }
    } else if (target == L"chrome_history") {
        wchar_t path[MAX_PATH]{};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path))) {
            resolved = std::wstring(path) + L"\\Google\\Chrome\\User Data";
        }
    } else if (target == L"edge_history") {
        wchar_t path[MAX_PATH]{};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path))) {
            resolved = std::wstring(path) + L"\\Microsoft\\Edge\\User Data";
        }
    } else if (target == L"everything") {
        resolved = (g_app.exeDir / L"programms" / L"Everything.exe").wstring();
    } else if (target == L"lastactivity") {
        resolved = (g_app.exeDir / L"programms" / L"LastActivityView.exe").wstring();
    } else if (target == L"executedprograms") {
        resolved = (g_app.exeDir / L"programms" / L"ExecutedProgramsList.exe").wstring();
    } else if (target == L"cachedprograms") {
        resolved = (g_app.exeDir / L"programms" / L"CachedProgramsList.exe").wstring();
    } else if (target == L"journaltrace") {
        resolved = (g_app.exeDir / L"programms" / L"JournalTrace.exe").wstring();
    } else if (target == L"usbdeview") {
        resolved = (g_app.exeDir / L"programms" / L"USBDeview.exe").wstring();
    } else if (target == L"usbdrivelog") {
        resolved = (g_app.exeDir / L"programms" / L"USBDriveLog.exe").wstring();
    } else if (target == L"shellbags") {
        resolved = (g_app.exeDir / L"programms" / L"shellbag_analyzer_cleaner.exe").wstring();
    } else if (target == L"regedit") {
        resolved = L"regedit.exe";
    } else if (target == L"registry_run") {
        ShellExecuteW(g_app.hwnd, L"open", L"regedit.exe", L"/m HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", nullptr, SW_SHOWNORMAL);
        return;
    } else if (target == L"startup") {
        resolved = L"shell:startup";
    } else if (target == L"taskschd") {
        resolved = L"taskschd.msc";
    } else if (target == L"services") {
        resolved = L"services.msc";
    } else if (target == L"drivers_dir") {
        wchar_t win[MAX_PATH]{};
        GetWindowsDirectoryW(win, static_cast<UINT>(std::size(win)));
        resolved = std::wstring(win) + L"\\System32\\drivers";
    } else if (target == L"hosts") {
        wchar_t win[MAX_PATH]{};
        GetWindowsDirectoryW(win, static_cast<UINT>(std::size(win)));
        resolved = std::wstring(win) + L"\\System32\\drivers\\etc\\hosts";
    } else if (target == L"firewall") {
        resolved = L"wf.msc";
    } else if (target == L"installed_apps") {
        resolved = L"appwiz.cpl";
    } else if (target == L"device_manager") {
        resolved = L"devmgmt.msc";
    } else if (target == L"taskmgr") {
        resolved = L"taskmgr.exe";
    }

    ShellExecuteW(g_app.hwnd, L"open", resolved.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void HandleWebMessage(const std::wstring& message) {
    const auto type = FindJsonValue(message, L"type");
    if (type == L"ready") {
        SendToWeb(ProfilesJson());
        SendToWeb(std::wstring(L"{\"type\":\"adminState\",\"isAdmin\":") +
                  (Ns_IsAdministrator() ? L"true" : L"false") + L"}");
        return;
    }

    if (type == L"scan") {
        auto profile = FindJsonValue(message, L"profile");
        auto mode = FindJsonValue(message, L"mode");
        if (profile == L"cs") {
            SendToWeb(L"{\"type\":\"scanError\",\"profile\":\"cs\",\"message\":\"CS profile is soon...\"}");
            return;
        }
        if (profile.empty()) profile = L"scum";
        if (mode.empty()) mode = L"full";
        RunScanAsync(std::move(profile), std::move(mode));
        return;
    }

    if (type == L"open") {
        OpenExternal(FindJsonValue(message, L"target"));
        return;
    }

    if (type == L"reveal") {
        RevealPath(FindJsonValue(message, L"path"));
        return;
    }

    if (type == L"steamProfile") {
        auto steamId = FindJsonValue(message, L"steamId");
        if (!steamId.empty()) FetchSteamProfileAsync(std::move(steamId));
    }
}

std::wstring UriToAssetPath(std::wstring uri) {
    // Drop scheme://host, keep the path only.
    const auto scheme = uri.find(L"://");
    if (scheme != std::wstring::npos) uri = uri.substr(scheme + 3);
    const auto slash = uri.find(L'/');
    std::wstring path = (slash == std::wstring::npos) ? L"" : uri.substr(slash + 1);

    // Strip query string / fragment.
    const auto cut = path.find_first_of(L"?#");
    if (cut != std::wstring::npos) path = path.substr(0, cut);

    // Minimal percent-decoding (asset names are plain, but be safe).
    std::wstring decoded;
    decoded.reserve(path.size());
    for (size_t i = 0; i < path.size(); ++i) {
        if (path[i] == L'%' && i + 2 < path.size() && iswxdigit(path[i + 1]) && iswxdigit(path[i + 2])) {
            auto hex = [](wchar_t c) -> int {
                if (c >= L'0' && c <= L'9') return c - L'0';
                if (c >= L'a' && c <= L'f') return c - L'a' + 10;
                return c - L'A' + 10;
            };
            decoded.push_back(static_cast<wchar_t>((hex(path[i + 1]) << 4) | hex(path[i + 2])));
            i += 2;
        } else {
            decoded.push_back(path[i]);
        }
    }
    return decoded;
}

const WebAsset* FindWebAsset(std::wstring path) {
    while (!path.empty() && path.front() == L'/') path.erase(path.begin());
    if (path.empty()) path = L"index.html";
    for (int i = 0; i < kWebAssetCount; ++i) {
        if (path == kWebAssets[i].path) return &kWebAssets[i];
    }
    return nullptr;
}

void ServeEmbedded(ICoreWebView2WebResourceRequestedEventArgs* args, const std::wstring& uri) {
    if (!g_app.environment) return;

    const WebAsset* asset = FindWebAsset(UriToAssetPath(uri));
    ComPtr<ICoreWebView2WebResourceResponse> response;

    if (!asset) {
        g_app.environment->CreateWebResourceResponse(
            nullptr, 404, L"Not Found", L"Content-Type: text/plain; charset=utf-8", &response);
        if (response) args->put_Response(response.Get());
        return;
    }

    const HMODULE mod = GetModuleHandleW(nullptr);
    const HRSRC hRes = FindResourceW(mod, MAKEINTRESOURCEW(asset->resourceId), RT_RCDATA);
    if (!hRes) return;
    const HGLOBAL hData = LoadResource(mod, hRes);
    const DWORD size = SizeofResource(mod, hRes);
    const BYTE* bytes = static_cast<const BYTE*>(LockResource(hData));
    if (!bytes) return;

    ComPtr<IStream> stream;
    stream.Attach(SHCreateMemStream(bytes, size));
    if (!stream) return;

    const std::wstring headers =
        std::wstring(L"Content-Type: ") + asset->mime + L"\r\nCache-Control: no-cache";
    g_app.environment->CreateWebResourceResponse(
        stream.Get(), 200, L"OK", headers.c_str(), &response);
    if (response) args->put_Response(response.Get());
}

void ResizeWebView() {
    if (!g_app.controller) return;
    RECT bounds{};
    GetClientRect(g_app.hwnd, &bounds);
    g_app.controller->put_Bounds(bounds);
}

void InitWebView() {
    const auto userData = (g_app.exeDir / L"webview-data").wstring();
    CreateCoreWebView2EnvironmentWithOptions(
        nullptr,
        userData.c_str(),
        nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [](HRESULT result, ICoreWebView2Environment* env) -> HRESULT {
                if (FAILED(result) || !env) return result;

                g_app.environment = env;

                env->CreateCoreWebView2Controller(
                    g_app.hwnd,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [](HRESULT controllerResult, ICoreWebView2Controller* controller) -> HRESULT {
                            if (FAILED(controllerResult) || !controller) return controllerResult;

                            g_app.controller = controller;
                            controller->get_CoreWebView2(&g_app.webview);
                            ResizeWebView();

                            ComPtr<ICoreWebView2Settings> settings;
                            if (SUCCEEDED(g_app.webview->get_Settings(&settings)) && settings) {
                                settings->put_AreDefaultContextMenusEnabled(FALSE);
                                settings->put_AreDevToolsEnabled(TRUE);
                                settings->put_IsStatusBarEnabled(FALSE);
                            }

                            EventRegistrationToken token{};
                            g_app.webview->add_WebMessageReceived(
                                Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                                    [](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                                        PWSTR raw = nullptr;
                                        if (SUCCEEDED(args->TryGetWebMessageAsString(&raw))) {
                                            HandleWebMessage(raw ? raw : L"");
                                            CoTaskMemFree(raw);
                                        }
                                        return S_OK;
                                    }).Get(),
                                &token);

                            // Serve every asset under the virtual origin from the
                            // resources embedded in the executable.
                            g_app.webview->AddWebResourceRequestedFilter(
                                (std::wstring(kAppOrigin) + L"*").c_str(),
                                COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL);

                            EventRegistrationToken resourceToken{};
                            g_app.webview->add_WebResourceRequested(
                                Callback<ICoreWebView2WebResourceRequestedEventHandler>(
                                    [](ICoreWebView2*, ICoreWebView2WebResourceRequestedEventArgs* args) -> HRESULT {
                                        ComPtr<ICoreWebView2WebResourceRequest> request;
                                        if (FAILED(args->get_Request(&request)) || !request) return S_OK;
                                        PWSTR uriRaw = nullptr;
                                        if (SUCCEEDED(request->get_Uri(&uriRaw)) && uriRaw) {
                                            ServeEmbedded(args, uriRaw);
                                            CoTaskMemFree(uriRaw);
                                        }
                                        return S_OK;
                                    }).Get(),
                                &resourceToken);

                            g_app.webview->Navigate((std::wstring(kAppOrigin) + L"index.html").c_str());
                            return S_OK;
                        }).Get());

                return S_OK;
            }).Get());
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_SIZE:
        ResizeWebView();
        return 0;
    case WM_SCAN_RESULT: {
        std::unique_ptr<std::wstring> payload(reinterpret_cast<std::wstring*>(lParam));
        if (payload && payload->find(L"\"type\":\"steamProfile\"") == std::wstring::npos) {
            g_app.scanRunning = false;
        }
        if (payload) SendToWeb(*payload);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    g_app.exeDir = GetExeDirectory();

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.hInstance = instance;
    wc.lpfnWndProc = WndProc;
    wc.lpszClassName = kWindowClass;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_APP_ICON));
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    RegisterClassExW(&wc);

    g_app.hwnd = CreateWindowExW(
        0,
        kWindowClass,
        L"ScumCheckerV2",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        1260,
        820,
        nullptr,
        nullptr,
        instance,
        nullptr);

    if (!g_app.hwnd) {
        CoUninitialize();
        return 1;
    }

    ShowWindow(g_app.hwnd, showCommand);
    UpdateWindow(g_app.hwnd);
    InitWebView();

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    g_app.webview.Reset();
    g_app.controller.Reset();
    g_app.environment.Reset();
    CoUninitialize();
    return 0;
}
