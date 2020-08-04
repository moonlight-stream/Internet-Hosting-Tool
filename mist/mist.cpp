#include "mist.h"

#include <Ws2tcpip.h>
#include <stdio.h>
#include <assert.h>
#include <shellapi.h>
#include <objbase.h>
#include <WinHttp.h>
#include <wtsapi32.h>
#include <powerbase.h>
#include <VersionHelpers.h>

#pragma comment(lib, "miniupnpc.lib")
#pragma comment(lib, "libnatpmp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "powrprof.lib")

#define MINIUPNP_STATICLIB
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#define NATPMP_STATICLIB
#include <natpmp.h>

#define LOOPBACK_SERVER_PORT_OFFSET -10000

static struct port_entry {
    int proto;
    int port;
    bool withServer;
} k_Ports[] = {
    {IPPROTO_TCP, 47984, false},
    {IPPROTO_TCP, 47989, false},
    {IPPROTO_TCP, 48010, true},
    {IPPROTO_UDP, 47998, true},
    {IPPROTO_UDP, 47999, true},
    {IPPROTO_UDP, 48000, true},

#if 0
    // These are not currently used, so let's
    // avoid testing them for now.
    {IPPROTO_UDP, 48002, true},
    {IPPROTO_UDP, 48010, true}
#endif
};

char logFilePath[MAX_PATH + 1];

enum MessagePriority {
    MpInfo,
    MpWarn,
    MpError
};

VOID CALLBACK MsgBoxHelpCallback(LPHELPINFO lpHelpInfo)
{
    const char* helpUrl = (const char*)lpHelpInfo->dwContextId;

    if (!helpUrl) {
        return;
    }

    // It's recommended to initialize COM before calling ShellExecute()
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    ShellExecuteA(nullptr, "open", helpUrl, nullptr, nullptr, SW_SHOWNORMAL);
}

void DisplayMessage(const char* message, const char* helpUrl = nullptr, MessagePriority priority = MpError, bool terminal = true)
{
    fprintf(CONSOLE_OUT, "%s\n", message);
    fprintf(LOG_OUT, "%s\n", message);

    if (terminal) {
        char logPath[MAX_PATH + 1];
        FILE* f;

        fprintf(LOG_OUT, "--------------- CURRENT MISS LOG -------------------\n");

        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\miss-current.log", logPath, sizeof(logPath));
        f = fopen(logPath, "r");
        if (f != nullptr) {
            char buffer[1024];
            while (!feof(f)) {
                int bytesRead = fread(buffer, 1, ARRAYSIZE(buffer), f);
                fwrite(buffer, 1, bytesRead, LOG_OUT);
            }
            fclose(f);
        }
        else {
            fprintf(LOG_OUT, "Failed to find current MISS log\n");
        }

        fprintf(LOG_OUT, "\n----------------- OLD MISS LOG ---------------------\n");

        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\miss-old.log", logPath, sizeof(logPath));
        f = fopen(logPath, "r");
        if (f != nullptr) {
            char buffer[1024];
            while (!feof(f)) {
                int bytesRead = fread(buffer, 1, ARRAYSIZE(buffer), f);
                fwrite(buffer, 1, bytesRead, LOG_OUT);
            }
            fclose(f);
        }
        else {
            fprintf(LOG_OUT, "Failed to find old MISS log\n");
        }

        fprintf(LOG_OUT, "--------------- CURRENT GSV6FWD LOG -------------------\n");

        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\GSv6Fwd-current.log", logPath, sizeof(logPath));
        f = fopen(logPath, "r");
        if (f != nullptr) {
            char buffer[1024];
            while (!feof(f)) {
                int bytesRead = fread(buffer, 1, ARRAYSIZE(buffer), f);
                fwrite(buffer, 1, bytesRead, LOG_OUT);
            }
            fclose(f);
        }
        else {
            fprintf(LOG_OUT, "Failed to find current GSv6Fwd log\n");
        }

        fprintf(LOG_OUT, "\n----------------- OLD GSV6FWD LOG ---------------------\n");

        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\GSv6Fwd-old.log", logPath, sizeof(logPath));
        f = fopen(logPath, "r");
        if (f != nullptr) {
            char buffer[1024];
            while (!feof(f)) {
                int bytesRead = fread(buffer, 1, ARRAYSIZE(buffer), f);
                fwrite(buffer, 1, bytesRead, LOG_OUT);
            }
            fclose(f);
        }
        else {
            fprintf(LOG_OUT, "Failed to find old GSv6Fwd log\n");
        }

        fflush(LOG_OUT);
    }

    MSGBOXPARAMSA msgParams;
    msgParams.cbSize = sizeof(msgParams);
    msgParams.hwndOwner = nullptr;
    msgParams.hInstance = nullptr;
    msgParams.lpszText = message;
    msgParams.lpszCaption = "Moonlight Internet Streaming Tester";
    msgParams.dwStyle = MB_OK | MB_TOPMOST | MB_SETFOREGROUND;
    if (helpUrl) {
        msgParams.dwStyle |= MB_HELP;
    }
    switch (priority) {
    case MpInfo:
        msgParams.dwStyle |= MB_ICONINFORMATION;
        break;
    case MpWarn:
        msgParams.dwStyle |= MB_ICONWARNING;
        break;
    case MpError:
        msgParams.dwStyle |= MB_ICONERROR;
        break;
    }
    msgParams.lpfnMsgBoxCallback = MsgBoxHelpCallback;
    msgParams.dwContextHelpId = (DWORD_PTR)helpUrl;
    msgParams.dwLanguageId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    MessageBoxIndirectA(&msgParams);

    if (priority != MpInfo && terminal) {
        UINT flags = MB_YESNO | MB_TOPMOST | MB_SETFOREGROUND | MB_ICONINFORMATION;
        switch (MessageBoxA(nullptr, "Would you like to view the troubleshooting log?\n\nYou will need to provide this log if you ask for help on the Moonlight Discord server.",
            "Moonlight Internet Streaming Tester", flags))
        {
        case IDYES:
            // It's recommended to initialize COM before calling ShellExecute()
            CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
            ShellExecuteA(nullptr, "open", logFilePath, nullptr, nullptr, SW_SHOWNORMAL);
            break;
        }
    }
}

bool ExecuteCommand(PCSTR command, PCHAR outputBuffer, DWORD outputBufferLength)
{
    SECURITY_ATTRIBUTES attribs;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE outReadHandle;
    DWORD bytesRead = 0;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;

    ZeroMemory(&attribs, sizeof(attribs));
    attribs.nLength = sizeof(attribs);
    attribs.bInheritHandle = TRUE;

    if (!CreatePipe(&outReadHandle, &si.hStdOutput, &attribs, 0))
    {
        fprintf(LOG_OUT, "CreatePipe() failed: %d\n", GetLastError());
        return false;
    }

    si.hStdError = si.hStdOutput;

    if (!CreateProcess(NULL, (LPSTR)command, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        fprintf(LOG_OUT, "CreateProcess() failed: %d\n", GetLastError());
        CloseHandle(si.hStdOutput);
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(si.hStdOutput);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (!ReadFile(outReadHandle, outputBuffer, outputBufferLength, &bytesRead, NULL))
    {
        fprintf(LOG_OUT, "ReadFile() failed: %d\n", GetLastError());
        CloseHandle(outReadHandle);
        return false;
    }

    outputBuffer[bytesRead] = 0;
    CloseHandle(outReadHandle);
    return true;
}

bool IsGameStreamEnabled()
{
    DWORD error;
    DWORD enabled;
    DWORD len;
    HKEY key;

    error = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\NVIDIA Corporation\\NvStream", 0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (error != ERROR_SUCCESS) {
        fprintf(LOG_OUT, "RegOpenKeyEx() failed: %d\n", error);
        DisplayMessage("GeForce Experience was not detected on this PC. Make sure you're installing this utility on your GeForce GameStream-compatible PC, not the device running Moonlight.",
            "https://github.com/moonlight-stream/moonlight-docs/wiki/Setup-Guide");
        return false;
    }

    len = sizeof(enabled);
    error = RegQueryValueExA(key, "EnableStreaming", nullptr, nullptr, (LPBYTE)&enabled, &len);
    RegCloseKey(key);
    if (error != ERROR_SUCCESS || !enabled) {
        // GFE may not even write EnableStreaming until the user enables GameStream for the first time
        if (error != ERROR_SUCCESS) {
            fprintf(LOG_OUT, "RegQueryValueExA() failed: %d\n", error);
        }
        DisplayMessage("GameStream is not enabled in GeForce Experience. Please open GeForce Experience settings, navigate to the Shield tab, and turn GameStream on.",
            "https://github.com/moonlight-stream/moonlight-docs/wiki/Setup-Guide");
        return false;
    }
    else {
        fprintf(LOG_OUT, "GeForce Experience installed and GameStream is enabled\n");
        return true;
    }
}

bool IsConsoleSessionActive()
{
    PWTS_SESSION_INFO_1 sessionInfo;
    DWORD sessionCount;
    DWORD level;
    bool ret;
    DWORD activeSessionId = WTSGetActiveConsoleSessionId();

    if (activeSessionId == 0xFFFFFFFF) {
        fprintf(LOG_OUT, "No active console session detected\n");
        return false;
    }

    level = 1;
    if (!WTSEnumerateSessionsEx(WTS_CURRENT_SERVER_HANDLE, &level, 0, &sessionInfo, &sessionCount)) {
        fprintf(LOG_OUT, "WTSEnumerateSessionsEx() failed: %d\n", GetLastError());
        return false;
    }

    ret = false;
    for (int i = 0; i < sessionCount; i++)
    {
        if (sessionInfo[i].SessionId == activeSessionId) {
            if (sessionInfo[i].pUserName != nullptr) {
                fprintf(LOG_OUT, "Session %d has active user\n", sessionInfo[i].SessionId);
                ret = true;
                break;
            }
        }
    }

    WTSFreeMemoryExW(WTSTypeSessionInfoLevel1, sessionInfo, sessionCount);
    return ret;
}

bool IsSleepEnabled()
{
    SYSTEM_POWER_POLICY powerPolicy;

    if (CallNtPowerInformation(SystemPowerPolicyAc, NULL, 0, &powerPolicy, sizeof(powerPolicy)) < 0) {
        return false;
    }

    return powerPolicy.IdleTimeout != 0 && powerPolicy.Idle.Action == PowerActionSleep;
}

bool IsHibernationEnabled()
{
    SYSTEM_POWER_POLICY powerPolicy;

    if (CallNtPowerInformation(SystemPowerPolicyAc, NULL, 0, &powerPolicy, sizeof(powerPolicy)) < 0) {
        return false;
    }

    return powerPolicy.DozeS4Timeout != 0 || (powerPolicy.IdleTimeout != 0 && powerPolicy.Idle.Action == PowerActionHibernate);
}

bool IsLocalNetworkAccessBlocked()
{
    MIB_IPFORWARDROW route;
    DWORD error;
    SOCKADDR_IN sin;
    SOCKET s;
    
    error = GetBestRoute(0, 0, &route);
    if (error != NO_ERROR) {
        fprintf(LOG_OUT, "GetBestRoute() failed: %d\n", error);
        return false;
    }

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        fprintf(LOG_OUT, "socket() failed: %d\n", error);
        return false;
    }

    RtlZeroMemory(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.S_un.S_addr = route.dwForwardNextHop;
    sin.sin_port = htons(80);

    if (connect(s, (PSOCKADDR)&sin, sizeof(sin)) == 0) {
        error = NO_ERROR;
        fprintf(LOG_OUT, "connect(%s, %d) successful\n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    }
    else {
        error = WSAGetLastError();
        fprintf(LOG_OUT, "connect(%s, %d) failed: %d\n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), error);
    }

    closesocket(s);

    return error == WSAEACCES;
}

bool IsZeroTierInstalled()
{
    DWORD error;
    HKEY key;

    error = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\ZeroTier, Inc.\\ZeroTier One", 0, KEY_READ | KEY_WOW64_32KEY, &key);
    if (error != ERROR_SUCCESS) {
        return false;
    }

    RegCloseKey(key);
    return true;
}

enum PortTestStatus {
    PortTestOk,
    PortTestError,
    PortTestUnknown
};
PortTestStatus TestPort(PSOCKADDR_STORAGE addr, int proto, int port, bool withServer, bool isLoopbackRelay)
{
    SOCKET clientSock = INVALID_SOCKET, serverSock = INVALID_SOCKET;
    int err;

    clientSock = socket(addr->ss_family, proto == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM, proto);
    if (clientSock == INVALID_SOCKET) {
        fprintf(LOG_OUT, "socket() failed: %d\n", WSAGetLastError());
        return PortTestError;
    }

    if (withServer) {
        // Even if we are testing IPv6, our server socket should still be on IPv4 to allow the
        // IPv6 relay to do its job (since it's already bound to all GFE ports on v6)
        serverSock = socket(AF_INET, proto == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM, proto);
        if (serverSock == INVALID_SOCKET) {
            fprintf(LOG_OUT, "socket() failed: %d\n", WSAGetLastError());
            closesocket(clientSock);
            return PortTestError;
        }

        SOCKADDR_IN sin = {};
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        err = bind(serverSock, (struct sockaddr*)&sin, sizeof(sin));
        if (err == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEADDRINUSE) {
                // If someone is already listening (perhaps GFE is currently streaming),
                // we can proceed if it's a TCP connection unless it's a loopback relay
                // which would give us a false positive result.
                if (proto == IPPROTO_TCP && !isLoopbackRelay) {
                    closesocket(serverSock);
                    serverSock = INVALID_SOCKET;
                }
                else {
                    // We can't continue to test for UDP ports.
                    fprintf(LOG_OUT, "Unknown (in use)\n");
                    closesocket(clientSock);
                    closesocket(serverSock);
                    return PortTestUnknown;
                }
            }
            else {
                fprintf(LOG_OUT, "bind() failed: %d\n", WSAGetLastError());
                closesocket(clientSock);
                closesocket(serverSock);
                return PortTestError;
            }
        }

        if (proto == IPPROTO_TCP && serverSock != INVALID_SOCKET) {
            err = listen(serverSock, 1);
            if (err == SOCKET_ERROR) {
                fprintf(LOG_OUT, "listen() failed: %d\n", WSAGetLastError());
                closesocket(clientSock);
                closesocket(serverSock);
                return PortTestError;
            }
        }
    }

    ULONG nbIo = 1;
    err = ioctlsocket(clientSock, FIONBIO, &nbIo);
    if (err == SOCKET_ERROR) {
        fprintf(LOG_OUT, "ioctlsocket() failed: %d\n", WSAGetLastError());
        closesocket(clientSock);
        if (serverSock != INVALID_SOCKET) {
            closesocket(serverSock);
        }
        return PortTestError;
    }

    SOCKADDR_IN6 sin6;
    int addrLen = addr->ss_family == AF_INET ?
        sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6);

    RtlCopyMemory(&sin6, addr, addrLen);
    sin6.sin6_port = htons(port + (isLoopbackRelay ? LOOPBACK_SERVER_PORT_OFFSET : 0));

    if (proto == IPPROTO_TCP) {
        err = connect(clientSock, (struct sockaddr*)&sin6, addrLen);
        if (err == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
            fprintf(LOG_OUT, "connect() failed: %d\n", WSAGetLastError());
        }
        else {
            struct timeval timeout = {};
            fd_set fds;

            FD_ZERO(&fds);

            if (serverSock != INVALID_SOCKET) {
                FD_SET(serverSock, &fds);
            }
            else {
                FD_SET(clientSock, &fds);
            }

            // If we have a server socket, listen for the accept() instead of the
            // connect() so we can be compatible with the loopback relay.
            timeout.tv_sec = 3;
            err = select(0,
                serverSock != INVALID_SOCKET ? &fds : nullptr,
                serverSock == INVALID_SOCKET ? &fds : nullptr,
                nullptr, &timeout);
            if (err == 1) {
                // Our FD was signalled for connect() or accept() completion
                fprintf(LOG_OUT, "Success\n");
            }
            else if (err == 0) {
                // Timed out
                fprintf(LOG_OUT, "Timeout\n");
            }
            else {
                fprintf(LOG_OUT, "select() failed: %d\n", WSAGetLastError());
            }
        }

        closesocket(clientSock);
        if (serverSock != INVALID_SOCKET) {
            closesocket(serverSock);
        }

        return err == 1 ? PortTestOk : PortTestError;
    }
    else {
        const char testMsg[] = "moonlight-test";

        // Send several test packets to ensure a random lost packet doesn't make the test fail
        for (int i = 0; i < 5; i++) {
            err = sendto(clientSock, testMsg, sizeof(testMsg), 0, (struct sockaddr*)&sin6, addrLen);
            if (err == SOCKET_ERROR) {
                fprintf(LOG_OUT, "sendto() failed: %d\n", WSAGetLastError());
                closesocket(clientSock);
                closesocket(serverSock);
                return PortTestError;
            }

            Sleep(200);
        }

        struct timeval timeout = {};
        fd_set fds;

        FD_ZERO(&fds);
        FD_SET(serverSock, &fds);

        timeout.tv_sec = 2;
        err = select(0, &fds, nullptr, nullptr, &timeout);
        if (err == 1) {
            // Our FD was signalled for data available
            fprintf(LOG_OUT, "Success\n");
        }
        else if (err == 0) {
            // Timed out
            fprintf(LOG_OUT, "Timeout\n");
        }
        else {
            fprintf(LOG_OUT, "select() failed: %d\n", WSAGetLastError());
        }

        closesocket(clientSock);
        closesocket(serverSock);

        return err == 1 ? PortTestOk : PortTestError;
    }
}

PortTestStatus TestHttpPort(PSOCKADDR_STORAGE addr, int port, bool isLoopbackRelay)
{
    HINTERNET hSession = nullptr;
    HINTERNET hConnection = nullptr;
    HINTERNET hRequest = nullptr;
    PortTestStatus result;

    hSession = WinHttpOpen(L"MIST", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession == nullptr) {
        fprintf(LOG_OUT, "WinHttpOpen() failed: %d\n", GetLastError());
        result = PortTestError;
        goto Exit;
    }

    // WinHTTP's default timeouts are very long. Set them to something more reasonable.
    if (!WinHttpSetTimeouts(hSession, 0, 3000, 5000, 5000)) {
        fprintf(LOG_OUT, "WinHttpSetTimeouts() failed: %d\n", GetLastError());
    }

    // Windows 8.1 enabled TLSv1.2 for WinHTTP by default (8.0 enables it for Schannel but not WinHTTP)
    // https://docs.microsoft.com/en-us/security/engineering/solving-tls1-problem
    if (!IsWindows8Point1OrGreater()) {
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 |
                          WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 |
                          WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;

        if (!WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
            fprintf(LOG_OUT, "WinHttpSetOption(WINHTTP_OPTION_SECURE_PROTOCOLS) failed: %d\n", GetLastError());
        }
    }

    WCHAR urlEscapedAddr[INET6_ADDRSTRLEN + 2];
    if (addr->ss_family == AF_INET) {
        InetNtopW(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, urlEscapedAddr, ARRAYSIZE(urlEscapedAddr));
    }
    else {
        // The address string must be escaped for usage in URLs
        urlEscapedAddr[0] = L'[';
        InetNtopW(AF_INET6, &((struct sockaddr_in6*)addr)->sin6_addr, &urlEscapedAddr[1], INET6_ADDRSTRLEN);
        wcscat_s(urlEscapedAddr, L"]");
    }

    hConnection = WinHttpConnect(hSession, urlEscapedAddr, port + (isLoopbackRelay ? LOOPBACK_SERVER_PORT_OFFSET : 0), NULL);
    if (hConnection == nullptr) {
        fprintf(LOG_OUT, "WinHttpConnect() failed: %d\n", GetLastError());
        result = PortTestError;
        goto Exit;
    }

    hRequest = WinHttpOpenRequest(hConnection, L"GET", L"/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  port == 47984 ? WINHTTP_FLAG_SECURE : 0);
    if (hConnection == nullptr) {
        fprintf(LOG_OUT, "WinHttpOpenRequest() failed: %d\n", GetLastError());
        result = PortTestError;
        goto Exit;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(hRequest, NULL)) {
        if (GetLastError() == ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED) {
            // This is expected for our HTTPS connection
            fprintf(LOG_OUT, "Success\n");
            result = PortTestOk;
        }
        else {
            // CANNOT_CONNECT is the "expected" error
            if (GetLastError() == ERROR_WINHTTP_CANNOT_CONNECT) {
                fprintf(LOG_OUT, "Failed\n");
            }
            else {
                fprintf(LOG_OUT, "Failed: %d\n", GetLastError());
            }

            result = PortTestError;
        }

        goto Exit;
    }
    else {
        fprintf(LOG_OUT, "Success\n");
        result = PortTestOk;
    }

Exit:
    if (hRequest != nullptr) {
        WinHttpCloseHandle(hRequest);
    }
    if (hConnection != nullptr) {
        WinHttpCloseHandle(hConnection);
    }
    if (hSession != nullptr) {
        WinHttpCloseHandle(hSession);
    }

    return result;
}

bool TestAllPorts(PSOCKADDR_STORAGE addr, char* portMsg, int portMsgLen, bool isLoopbackRelay, bool consolePrint, bool* allPortsFailed = nullptr)
{
    bool ret = true;

    if (allPortsFailed) {
        *allPortsFailed = true;
    }

    for (int i = 0; i < ARRAYSIZE(k_Ports); i++) {
        PortTestStatus status;

        if (consolePrint) {
            fprintf(CONSOLE_OUT, "\tTesting %s %d...\n",
                k_Ports[i].proto == IPPROTO_TCP ? "TCP" : "UDP",
                k_Ports[i].port);
        }

        if (!k_Ports[i].withServer) {
            // Test using a real HTTP client if the port wasn't totally dead.
            // This is required to confirm functionality with the loopback relay.
            assert(k_Ports[i].proto == IPPROTO_TCP);
            fprintf(LOG_OUT, "Testing TCP %d with HTTP traffic...", k_Ports[i].port);
            status = TestHttpPort(addr, k_Ports[i].port, isLoopbackRelay);
        }
        else {
            fprintf(LOG_OUT, "Testing %s %d...",
                k_Ports[i].proto == IPPROTO_TCP ? "TCP" : "UDP",
                k_Ports[i].port);
            status = TestPort(addr, k_Ports[i].proto, k_Ports[i].port, k_Ports[i].withServer, isLoopbackRelay);
        }

        if (status != PortTestOk) {
            // If we got an unknown result, assume it matches with whatever
            // we've gotten so far.
            if (status == PortTestError || !ret) {
                if (portMsg != NULL && portMsgLen > 0) {
                    int msgLen = snprintf(portMsg, portMsgLen, "%s %d\n",
                        k_Ports[i].proto == IPPROTO_TCP ? "TCP" : "UDP",
                        k_Ports[i].port);
                    portMsg += msgLen;
                    portMsgLen -= msgLen;
                }

                // Keep going to check all ports and report the failing ones
                ret = false;
            }
        }
        else if (allPortsFailed) {
            *allPortsFailed = false;
        }
    }

    return ret;
}

bool FindLocalInterfaceIPAddress(int family, PSOCKADDR_STORAGE addr)
{
    SOCKET s;
    struct addrinfo hint = {};
    struct addrinfo* result;
    int err;

    fprintf(LOG_OUT, "Finding local %s address...", family == AF_INET ? "IPv4" : "IPv6");

    hint.ai_family = family;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_flags = AI_ADDRCONFIG;
    err = getaddrinfo("moonlight-stream.org", "443", &hint, &result);
    if (err != 0 || result == NULL) {
        fprintf(LOG_OUT, "getaddrinfo() failed: %d\n", err);
        return false;
    }

    s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET) {
        fprintf(LOG_OUT, "socket() failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        return false;
    }

    err = connect(s, (struct sockaddr*)result->ai_addr, result->ai_addrlen);
    if (err == SOCKET_ERROR) {
        fprintf(LOG_OUT, "connect() failed: %d\n", WSAGetLastError());
        closesocket(s);
        freeaddrinfo(result);
        return false;
    }

    freeaddrinfo(result);

    // Determine which local interface we bound to
    int nameLen = sizeof(*addr);
    err = getsockname(s, (struct sockaddr*)addr, &nameLen);
    if (err == SOCKET_ERROR) {
        fprintf(LOG_OUT, "getsockname() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return false;
    }

    char addrStr[INET6_ADDRSTRLEN];
    if (addr->ss_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, addrStr, sizeof(addrStr));
    }
    else {
        inet_ntop(AF_INET6, &((struct sockaddr_in6*)addr)->sin6_addr, addrStr, sizeof(addrStr));
    }
    fprintf(LOG_OUT, "%s\n", addrStr);

    return true;
}

bool FindZeroTierInterfaceAddress(PSOCKADDR_STORAGE addr)
{
    union {
        IP_ADAPTER_ADDRESSES addresses;
        char buffer[8192];
    };
    ULONG error;
    ULONG length;
    PIP_ADAPTER_ADDRESSES currentAdapter;
    PIP_ADAPTER_UNICAST_ADDRESS currentAddress;

    // Get all IPv4 interfaces
    length = sizeof(buffer);
    error = GetAdaptersAddresses(AF_INET,
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME,
        NULL,
        &addresses,
        &length);
    if (error != ERROR_SUCCESS) {
        fprintf(LOG_OUT, "GetAdaptersAddresses() failed: %d\n", error);
        return false;
    }

    currentAdapter = &addresses;
    while (currentAdapter != NULL) {
        // Look for ones that correspond to a ZeroTier device
        if (wcsstr(currentAdapter->Description, L"ZeroTier")) {
            // Check if this interface has the IP address we want
            currentAddress = currentAdapter->FirstUnicastAddress;
            while (currentAddress != NULL) {
                if (currentAddress->Address.lpSockaddr->sa_family == AF_INET) {
                    RtlCopyMemory(addr, currentAddress->Address.lpSockaddr, currentAddress->Address.iSockaddrLength);
                    return true;
                }

                currentAddress = currentAddress->Next;
            }
        }

        currentAdapter = currentAdapter->Next;
    }

    return false;
}

bool FindDuplicateDefaultInterfaces(void)
{
    union {
        IP_ADAPTER_ADDRESSES addresses;
        char buffer[8192];
    };
    ULONG error;
    ULONG length;
    MIB_IPFORWARDROW defaultRoute;
    PIP_ADAPTER_ADDRESSES currentAdapter;
    DWORD matchingInterfaces = 0;

    error = GetBestRoute(0, 0, &defaultRoute);
    if (error != NO_ERROR) {
        fprintf(LOG_OUT, "GetBestRoute() failed: %d\n", error);
        return false;
    }

    // Get all IPv4 interfaces
    length = sizeof(buffer);
    error = GetAdaptersAddresses(AF_INET,
        GAA_FLAG_SKIP_UNICAST |
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_INCLUDE_GATEWAYS |
        GAA_FLAG_SKIP_FRIENDLY_NAME,
        NULL,
        &addresses,
        &length);
    if (error != ERROR_SUCCESS) {
        fprintf(LOG_OUT, "GetAdaptersAddresses() failed: %d\n", error);
        return false;
    }

    currentAdapter = &addresses;
    while (currentAdapter != NULL) {
        if (currentAdapter->OperStatus == IfOperStatusUp &&
            currentAdapter->FirstGatewayAddress != NULL &&
            currentAdapter->FirstGatewayAddress->Address.iSockaddrLength == sizeof(SOCKADDR_IN)) {
            if (((PSOCKADDR_IN)currentAdapter->FirstGatewayAddress->Address.lpSockaddr)->sin_addr.S_un.S_addr == defaultRoute.dwForwardNextHop) {
                matchingInterfaces++;
            }
        }

        currentAdapter = currentAdapter->Next;
    }

    return matchingInterfaces > 1;
}

enum UPnPPortStatus {
    NOT_FOUND,
    OK,
    CONFLICTED,
    ERRORED
};
UPnPPortStatus UPnPCheckPort(struct UPNPUrls* urls, struct IGDdatas* data, int proto, const char* myAddr, int port, char* conflictMessage)
{
    char intClient[16];
    char intPort[6];
    char desc[80];
    char enabled[4];
    char leaseDuration[16];
    const char* protoStr;
    char portStr[6];

    snprintf(portStr, sizeof(portStr), "%d", port);
    switch (proto)
    {
    case IPPROTO_TCP:
        protoStr = "TCP";
        break;
    case IPPROTO_UDP:
        protoStr = "UDP";
        break;
    default:
        assert(false);
        return ERRORED;
    }

    fprintf(LOG_OUT, "Checking for UPnP port mapping for %s %s -> %s...", protoStr, portStr, myAddr);
    int err = UPNP_GetSpecificPortMappingEntry(
        urls->controlURL, data->first.servicetype, portStr, protoStr, nullptr,
        intClient, intPort, desc, enabled, leaseDuration);
    if (err == 714) {
        // NoSuchEntryInArray
        fprintf(LOG_OUT, "NOT FOUND\n");
        return NOT_FOUND;
    }
    else if (err == UPNPCOMMAND_SUCCESS) {
        if (!strcmp(myAddr, intClient)) {
            fprintf(LOG_OUT, "OK\n");
            return OK;
        }
        else {
            fprintf(LOG_OUT, "CONFLICT - %s %s\n", desc, intClient);
            snprintf(conflictMessage, 128, "%s (%s)", desc, intClient);
            return CONFLICTED;
        }
    }
    else {
        fprintf(LOG_OUT, "ERROR %d\n", err);
        return ERRORED;
    }
}

bool CheckWANAccess(PSOCKADDR_IN wanAddr, PSOCKADDR_IN reportedWanAddr, bool* foundPortForwardingRules, bool* igdDisconnected)
{
    natpmp_t natpmp;
    bool foundUpnpIgd = false;

    wanAddr->sin_family = AF_INET;
    reportedWanAddr->sin_family = AF_INET;
    *foundPortForwardingRules = false;
    *igdDisconnected = false;

    bool gotReportedWanAddress = false;
    int natPmpErr = initnatpmp(&natpmp, 0, 0);
    if (natPmpErr != 0) {
        fprintf(LOG_OUT, "initnatpmp() failed: %d\n", natPmpErr);
    }
    else {
        natPmpErr = sendpublicaddressrequest(&natpmp);
        if (natPmpErr < 0) {
            fprintf(LOG_OUT, "sendpublicaddressrequest() failed: %d\n", natPmpErr);
            closenatpmp(&natpmp);
        }
    }

    {
        fprintf(CONSOLE_OUT, "\tTesting UPnP...\n");

        int upnpErr;
        struct UPNPDev* ipv4Devs = upnpDiscoverAll(5000, nullptr, nullptr, UPNP_LOCAL_PORT_ANY, 0, 2, &upnpErr);

        struct UPNPUrls urls;
        struct IGDdatas data;
        char myAddr[128];
        char wanAddrStr[128];
        int ret = UPNP_GetValidIGD(ipv4Devs, &urls, &data, myAddr, sizeof(myAddr));
        if (ret != 0) {
            // Connected or disconnected IGD
            if (ret == 1 || ret == 2) {
                foundUpnpIgd = true;
                if (ret == 2) {
                    *igdDisconnected = true;
                }
                fprintf(LOG_OUT, "Discovered UPnP IGD at: %s\n", urls.controlURL);
                fprintf(LOG_OUT, "Detecting WAN IP address via UPnP...");
                ret = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, wanAddrStr);
                if (ret == UPNPCOMMAND_SUCCESS && strlen(wanAddrStr) > 0) {
                    reportedWanAddr->sin_addr.S_un.S_addr = inet_addr(wanAddrStr);
                    fprintf(LOG_OUT, "%s\n", wanAddrStr);

                    if (reportedWanAddr->sin_addr.S_un.S_addr != 0) {
                        gotReportedWanAddress = true;
                    }
                }
                else {
                    fprintf(LOG_OUT, "FAILED %d\n", ret);
                }

                char conflictMessage[512];
                *foundPortForwardingRules = true;
                for (int i = 0; i < ARRAYSIZE(k_Ports); i++) {
                    char conflictEntry[128];
                    UPnPPortStatus status = UPnPCheckPort(&urls, &data, k_Ports[i].proto, myAddr, k_Ports[i].port, conflictEntry);
                    if (status != OK) {
                        *foundPortForwardingRules = false;
                    }
                    switch (status)
                    {
                    case CONFLICTED:
                        snprintf(conflictMessage, sizeof(conflictMessage),
                            "Detected a port forwarding conflict with another PC on your network: %s\n\n"
                            "Remove that PC from your network or uninstall the Moonlight Internet Streaming Helper from it, then restart your router.",
                            conflictEntry);
                        DisplayMessage(conflictMessage);
                        return false;
                    default:
                        continue;
                    }
                }
            }
            else {
                fprintf(LOG_OUT, "No UPnP IGD detected\n");
            }

            FreeUPNPUrls(&urls);
        }
        else {
            fprintf(LOG_OUT, "No UPnP devices detected\n");
        }
    }

    // Use the delay of upnpDiscoverAll() to also allow the NAT-PMP endpoint time to respond
    if (natPmpErr >= 0) {
        fprintf(CONSOLE_OUT, "\tTesting NAT-PMP...\n");

        fprintf(LOG_OUT, "Detecting WAN IP address via NAT-PMP...");

        natpmpresp_t response;
        natPmpErr = readnatpmpresponseorretry(&natpmp, &response);
        closenatpmp(&natpmp);

        if (natPmpErr == 0) {
            char addrStr[64];
            reportedWanAddr->sin_addr = response.pnu.publicaddress.addr;
            inet_ntop(AF_INET, &response.pnu.publicaddress.addr, addrStr, sizeof(addrStr));
            fprintf(LOG_OUT, "%s\n", addrStr);
            if (reportedWanAddr->sin_addr.S_un.S_addr != 0) {
                gotReportedWanAddress = true;
                
                if (!foundUpnpIgd) {
                    // Just in case we have a NAT-PMP gateway that doesn't do NAT reflection
                    // let's assume it's all okay if we got any response at all
                    *foundPortForwardingRules = true;
                }
            }
        }
        else {
            fprintf(LOG_OUT, "FAILED %d\n", natPmpErr);
        }
    }

    fprintf(LOG_OUT, "Detecting WAN IP address via STUN...");
    fprintf(CONSOLE_OUT, "\tTesting STUN...\n");

    if (!getExternalAddressPortIP4(0, wanAddr)) {
        DisplayMessage("Unable to determine your public IP address. Please check your Internet connection or try again in a few minutes.");
        return false;
    }
    else {
        char addrStr[64];
        inet_ntop(AF_INET, &wanAddr->sin_addr, addrStr, sizeof(addrStr));
        fprintf(LOG_OUT, "%s\n", addrStr);

        if (!gotReportedWanAddress) {
            // If we didn't get anything from UPnP or NAT-PMP, just populate the reported
            // address with what we got from STUN
            *reportedWanAddr = *wanAddr;
        }
    }

    return true;
}

bool IsCGN(PSOCKADDR_IN wanAddr)
{
    DWORD addr = htonl(wanAddr->sin_addr.S_un.S_addr);

    // 100.64.0.0/10 - RFC6598 official CGN address
    if ((addr & 0xFFC00000) == 0x64400000) {
        return true;
    }

    return false;
}

bool IsDoubleNAT(PSOCKADDR_IN wanAddr)
{
    DWORD addr = htonl(wanAddr->sin_addr.S_un.S_addr);

    // 10.0.0.0/8
    if ((addr & 0xFF000000) == 0x0A000000) {
        return true;
    }
    // 172.16.0.0/12
    else if ((addr & 0xFFF00000) == 0xAC100000) {
        return true;
    }
    // 192.168.0.0/16
    else if ((addr & 0xFFFF0000) == 0xC0A80000) {
        return true;
    }

    return false;
}

int main(int argc, char* argv[])
{
    WSADATA wsaData;
    SYSTEMTIME time;
    char timeString[MAX_PATH + 1] = {};

    char tempPath[MAX_PATH + 1];
    GetTempPathA(sizeof(tempPath), tempPath);

    snprintf(logFilePath, sizeof(logFilePath), "%s\\%s", tempPath, "mis-test.log");
    freopen(logFilePath, "w", LOG_OUT);

    // Print a log header
    fprintf(LOG_OUT, "Moonlight Internet Streaming Tester v" VER_VERSION_STR "\n");

    // Print the current time
    GetSystemTime(&time);
    GetTimeFormatA(LOCALE_SYSTEM_DEFAULT, 0, &time, "hh':'mm':'ss tt", timeString, ARRAYSIZE(timeString));
    fprintf(LOG_OUT, "The current UTC time is: %s\n", timeString);

    // Print a console header
    fprintf(CONSOLE_OUT, "Moonlight Internet Streaming Tester v" VER_VERSION_STR "\n\n");

    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != NO_ERROR) {
        DisplayMessage("Unable to initialize WinSock");
        return err;
    }

    fprintf(CONSOLE_OUT, "Checking if GameStream is enabled...\n");

    // First check if GameStream is enabled
    if (!IsGameStreamEnabled()) {
        return -1;
    }

    if (!IsConsoleSessionActive()) {
        DisplayMessage("The system display is currently locked. You must sign in to your PC again to use GameStream.\n\n"
            "This is most often due to Microsoft Remote Desktop locking the screen. Use an alternate GameStream-compatible remote desktop solution like Chrome Remote Desktop or TeamViewer to unlock the PC and prevent this error in the future.",
            "https://github.com/moonlight-stream/moonlight-docs/wiki/Internet-Streaming-Errors#display-locked-error");
        return -1;
    }

    fprintf(CONSOLE_OUT, "Checking power settings...\n");

    if (IsSleepEnabled()) {
        DisplayMessage("This computer has sleep mode enabled. Sleep mode may prevent this PC from being available for streaming.\n\n"
            "Please ensure sleep is disabled in Power Options so this PC is always ready for streaming. Click the Help button for more information.",
            "https://github.com/moonlight-stream/moonlight-docs/wiki/Internet-Streaming-Errors#sleep-mode-enabled-warning", MpWarn, false);
    }

    if (IsHibernationEnabled()) {
        DisplayMessage("This computer has hibernation enabled. Hibernation may prevent this PC from being available for streaming.\n\n"
            "Please ensure hibernation is disabled in Power Options so this PC is always ready for streaming. Click the Help button for more information.",
            "https://github.com/moonlight-stream/moonlight-docs/wiki/Internet-Streaming-Errors#hibernation-enabled-warning", MpWarn, false);
    }

    fprintf(CONSOLE_OUT, "Checking network connections...\n");

    if (IsLocalNetworkAccessBlocked()) {
        DisplayMessage("Local network access appears to be blocked by another application installed on this PC.\n\n"
            "If you have firewall or VPN software installed, make sure it is configured to allow applications to access the local network. Click the Help button for guidance on fixing this issue.",
            "https://github.com/moonlight-stream/moonlight-docs/wiki/Internet-Streaming-Errors#local-network-access-blocked-error");
        return -1;
    }

    if (FindDuplicateDefaultInterfaces()) {
        DisplayMessage("This computer appears to have more than one connection to the same network (like both WiFi and Ethernet, for example).\n\n"
            "Please disconnect the extra connection(s) to ensure hosting works reliably over the Internet. If you are connected via WiFi and Ethernet, try disabling your WiFi connection.",
            "https://github.com/moonlight-stream/moonlight-docs/wiki/Internet-Streaming-Errors#multiple-connections-error", MpWarn, false);
    }

    fprintf(CONSOLE_OUT, "Checking for anti-virus and firewall software...\n");

    char wmicBuf[8192];
    if (ExecuteCommand("WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName", wmicBuf, sizeof(wmicBuf))) {
        fprintf(LOG_OUT, "AV products:\n%s", wmicBuf);
    }
    if (ExecuteCommand("WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path FirewallProduct Get displayName", wmicBuf, sizeof(wmicBuf))) {
        fprintf(LOG_OUT, "Firewall products:\n%s", wmicBuf);
        if (strstr(wmicBuf, "displayName")) {
            DisplayMessage("Detected anti-virus and/or firewall software installed on this system. This software may interfere with NVIDIA GameStream.\n\n"
                "Please try temporarily disabling your anti-virus or firewall software if you experience connection issues with Moonlight.",
                "https://github.com/moonlight-stream/moonlight-docs/wiki/Troubleshooting#known-application-compatibility-issues", MpInfo, false);
        }
    }


    union {
        SOCKADDR_STORAGE ss;
        SOCKADDR_IN sin;
        SOCKADDR_IN6 sin6;
    };
    char msgBuf[2048];
    char portMsgBuf[512];

    fprintf(CONSOLE_OUT, "Testing GameStream connectivity on this PC...\n");

    // Try to connect via IPv4 loopback
    ss = {};
    sin.sin_family = AF_INET;
    sin.sin_addr = in4addr_loopback;
    fprintf(LOG_OUT, "Testing GameStream ports via loopback\n");
    if (!TestAllPorts(&ss, portMsgBuf, sizeof(portMsgBuf), false, true)) {
        snprintf(msgBuf, sizeof(msgBuf),
            "Local GameStream connectivity check failed.\n\nFirst, try reinstalling GeForce Experience. If that doesn't resolve the problem, try temporarily disabling your antivirus and firewall.");
        DisplayMessage(msgBuf, "https://github.com/moonlight-stream/moonlight-docs/wiki/Troubleshooting");
        return -1;
    }
    
    // We do a special limited test pass for ZeroTier
    if (IsZeroTierInstalled()) {
        fprintf(LOG_OUT, "Found ZeroTier installed\n");

        if (!FindZeroTierInterfaceAddress(&ss)) {
            DisplayMessage("ZeroTier appears to be installed on this PC, but it's not connected to a network.\n\n"
                "If you are trying to host with ZeroTier, connect to your ZeroTier network and restart this test.\n\n"
                "If not, click OK and this test will continue assuming you aren't using ZeroTier.",
                "https://github.com/moonlight-stream/moonlight-docs/wiki/Setup-Guide#zerotier", MpInfo, false);
        }
        else {
            char zeroTierAddrStr[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &sin.sin_addr, zeroTierAddrStr, sizeof(zeroTierAddrStr));

            fprintf(LOG_OUT, "Found ZeroTier connected with address: %s\n", zeroTierAddrStr);

            if (strstr(zeroTierAddrStr, "169.254.")) {
                DisplayMessage("ZeroTier is active, but this PC has not been authorized to connect to your ZeroTier network.\n\n"
                    "Make sure you check the Auth checkbox for all network members on the ZeroTier Networks webpage.",
                    "https://github.com/moonlight-stream/moonlight-docs/wiki/Setup-Guide#zerotier");
                return -1;
            }

            // Try to connect via ZeroTier address
            fprintf(CONSOLE_OUT, "Testing GameStream connectivity using ZeroTier...\n");
            fprintf(LOG_OUT, "Testing GameStream ports via ZeroTier\n");
            if (!TestAllPorts(&ss, portMsgBuf, sizeof(portMsgBuf), false, true)) {
                snprintf(msgBuf, sizeof(msgBuf),
                    "ZeroTier connectivity check failed. This is almost always caused by a firewall on your computer blocking the connection.\n\nTry temporarily disabling your antivirus and firewall.");
                DisplayMessage(msgBuf, "https://github.com/moonlight-stream/moonlight-docs/wiki/Troubleshooting");
                return -1;
            }

            // If we get here, our testing is complete for ZeroTier
            snprintf(msgBuf, sizeof(msgBuf), "This PC is ready to host over the Internet with ZeroTier!\n\n"
                "Don't forget to connect to your ZeroTier network on your client before streaming over the Internet.\n\n"
                "After connecting ZeroTier, type following address into Moonlight's Add PC dialog: %s", zeroTierAddrStr);
            DisplayMessage(msgBuf, nullptr, MpInfo);
            return 0;
        }
    }

    if (!FindLocalInterfaceIPAddress(AF_INET, &ss) && !FindLocalInterfaceIPAddress(AF_INET6, &ss)) {
        DisplayMessage("Unable to perform GameStream connectivity check. Please check your Internet connection and try again.");
        return -1;
    }

    fprintf(CONSOLE_OUT, "Testing GameStream connectivity on your local network...\n");

    // Try to connect via LAN address
    fprintf(LOG_OUT, "Testing GameStream ports via local network\n");
    if (!TestAllPorts(&ss, portMsgBuf, sizeof(portMsgBuf), false, true)) {
        snprintf(msgBuf, sizeof(msgBuf),
            "Local network GameStream connectivity check failed. This is almost always caused by a firewall on your computer blocking the connection.\n\nTry temporarily disabling your antivirus and firewall.");
        DisplayMessage(msgBuf, "https://github.com/moonlight-stream/moonlight-docs/wiki/Troubleshooting");
        return -1;
    }

    bool igdDisconnected;
    SOCKADDR_IN locallyReportedWanAddr;
    char wanAddrStr[INET_ADDRSTRLEN];

    if (ss.ss_family == AF_INET) {
        bool rulesFound;

        fprintf(CONSOLE_OUT, "Detecting public IP address...\n");

        if (!CheckWANAccess(&sin, &locallyReportedWanAddr, &rulesFound, &igdDisconnected)) {
            return -1;
        }

        // Detect a double NAT by detecting STUN and and UPnP mismatches
        if (sin.sin_addr.S_un.S_addr != locallyReportedWanAddr.sin_addr.S_un.S_addr) {
            fprintf(LOG_OUT, "Testing GameStream ports via UPnP/NAT-PMP reported WAN address\n");

            // We don't actually care about the outcome here but it's nice to have in logs
            // to determine whether solving the double NAT will actually make Moonlight work.
            TestAllPorts((PSOCKADDR_STORAGE)&locallyReportedWanAddr, portMsgBuf, sizeof(portMsgBuf), false, false);

            fprintf(LOG_OUT, "Detected inconsistency between UPnP/NAT-PMP and STUN reported WAN addresses!\n");
        }

        inet_ntop(AF_INET, &sin.sin_addr, wanAddrStr, sizeof(wanAddrStr));
    }
    else {
        // Go directly to the relay check if we have only IPv6 connectivity
        igdDisconnected = false;
        locallyReportedWanAddr = {};
    }

    struct addrinfo hint = {};
    struct addrinfo* result;

    hint.ai_family = AF_UNSPEC;
    hint.ai_flags = AI_ADDRCONFIG;
    err = getaddrinfo("loopback-v2.moonlight-stream.org", NULL, &hint, &result);
    if (err != 0 || result == NULL) {
        fprintf(LOG_OUT, "getaddrinfo() failed: %d\n", err);
    }
    else {
        bool allPortsFailedOnV4 = true;

        // First try the relay server over IPv4. If this passes, it's considered a full success
        fprintf(LOG_OUT, "Testing GameStream ports via IPv4 loopback server\n");
        for (struct addrinfo* current = result; current != NULL; current = current->ai_next) {
            if (current->ai_family == AF_INET) {
                fprintf(CONSOLE_OUT, "Testing GameStream connectivity over the Internet using a relay server...\n");
                if (TestAllPorts((PSOCKADDR_STORAGE)current->ai_addr, portMsgBuf, sizeof(portMsgBuf), true, true, &allPortsFailedOnV4)) {
                    freeaddrinfo(result);
                    snprintf(msgBuf, sizeof(msgBuf), "This PC is ready to host over the Internet!\n\n"
                        "For the easiest setup, you should pair Moonlight to your gaming PC from your home network before trying to stream over the Internet.\n\n"
                        "If you can't, you can type the following address into Moonlight's Add PC dialog: %s", wanAddrStr);
                    DisplayMessage(msgBuf, nullptr, MpInfo);
                    return 0;
                }
            }
        }

        // If that fails, try the relay server over IPv6. If this passes, it will be a partial success
        fprintf(LOG_OUT, "Testing GameStream ports via IPv6 loopback server\n");
        for (struct addrinfo* current = result; current != NULL; current = current->ai_next) {
            if (current->ai_family == AF_INET6) {
                fprintf(CONSOLE_OUT, "Testing GameStream connectivity over the Internet using an IPv6 relay server...\n");
                // Pass the portMsgBuf only if we've detected an IPv6-only setup. Otherwise, we want to preserve
                // the failing ports from the IPv4 to display in the error dialog.
                if (TestAllPorts((PSOCKADDR_STORAGE)current->ai_addr,
                                    ss.ss_family == AF_INET6 ? portMsgBuf : NULL,
                                    ss.ss_family == AF_INET6 ? sizeof(portMsgBuf) : 0, true, true)) {
                    // We will terminate the test at the IPv6 limited connectivity warning in the following cases:
                    // 1) Double-NAT/CGN - indicates the connection is fundamentally limited to IPv6 for end-to-end connectivity
                    // 2) IPv6-only - indicates the connection is fundamentally limited to IPv6 for all connectivity
                    // 3) All ports failed the test with our IPv4 relay - This is one final heuristic to weed out IPv4 misconfigurations. If we have some ports open,
                    //                                                    it clearly indicates IPv4 support is possible, just currently misconfigured.
                    //
                    // Our last (implicit) heuristic is that we actually managed to establish an IPv6 connection. This means that there was either
                    // no IPv6 firewall (hopefully not) or that we were able to talk to a PCP/IGDv6 gateway to allow us through. Hopefully if we have
                    // a gateway that is unresponsive to UPnP/NAT-PMP, we wouldn't even be able to establish this connection so we would inherently fall
                    // to the checks below for IPv4 issues.
                    if (IsDoubleNAT(&locallyReportedWanAddr) || igdDisconnected || IsCGN(&locallyReportedWanAddr) || ss.ss_family == AF_INET6 || allPortsFailedOnV4) {
                        snprintf(msgBuf, sizeof(msgBuf), "This PC has limited connectivity for Internet hosting. It will work only for clients on certain networks.\n\n"
                            "If you want to try streaming with this configuration, you must pair Moonlight to your gaming PC from your home network before trying to stream over the Internet.\n\n"
                            "To get full connectivity, please contact your ISP and ask for a \"public IPv4 address\" which they may offer for free upon request. For more information and workarounds, click the Help button.");
                        DisplayMessage(msgBuf, "https://github.com/moonlight-stream/moonlight-docs/wiki/Internet-Streaming-Errors#limited-connectivity-for-hosting-error", MpWarn);
                        freeaddrinfo(result);
                        return 0;
                    }
                }
            }
        }

        freeaddrinfo(result);
    }

    // Many UPnP devices report IGD disconnected when double-NATed. If it was really offline,
    // we probably would not have even gotten past STUN.
    //
    // We try to tell double-NAT from CGN by checking if IPv6 connectivity is available. If it
    // is, we assume we're in a DS-Lite or similar configuration. If not, we'll assume it's a
    // real double-NAT setup.
    bool hasV6Connectivity = FindLocalInterfaceIPAddress(AF_INET6, &ss);
    if (IsCGN(&locallyReportedWanAddr) || ((IsDoubleNAT(&locallyReportedWanAddr) || igdDisconnected) && hasV6Connectivity)) {
        snprintf(msgBuf, sizeof(msgBuf), "Your ISP is running a Carrier-Grade NAT that is preventing you from hosting services like Moonlight on the Internet.\n\n"
            "Ask your ISP for a \"public IPv4 address\" which they may offer for free upon request. For more information and workarounds, click the Help button.");
        DisplayMessage(msgBuf, "https://github.com/moonlight-stream/moonlight-docs/wiki/Internet-Streaming-Errors#carrier-grade-nat-error");
    }
    else if ((IsDoubleNAT(&locallyReportedWanAddr) || igdDisconnected) /* && !hasV6Connectivity */) {
        snprintf(msgBuf, sizeof(msgBuf), "Your router appears be connected to the Internet through another router. Click the Help button for guidance on fixing this issue.");
        DisplayMessage(msgBuf, "https://github.com/moonlight-stream/moonlight-docs/wiki/Internet-Streaming-Errors#connected-through-another-router-error");
    }
    else {
        snprintf(msgBuf, sizeof(msgBuf), "Internet GameStream connectivity check failed.\n\n"
            "First, try restarting your router. If that fails, check that UPnP is enabled in your router settings. For more information and workarounds, click the Help button.\n\n"
            "The following ports were not forwarded properly:\n%s", portMsgBuf);
        DisplayMessage(msgBuf, "https://github.com/moonlight-stream/moonlight-docs/wiki/Internet-Streaming-Errors#internet-gamestream-connectivity-check-error");
    }

    return -1;
}