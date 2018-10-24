#define _CRT_RAND_S
#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <assert.h>
#include <shellapi.h>
#include <objbase.h>

#pragma comment(lib, "miniupnpc.lib")
#pragma comment(lib, "libnatpmp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MINIUPNP_STATICLIB
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#define NATPMP_STATICLIB
#include <natpmp.h>

#define STUN_MESSAGE_BINDING_REQUEST 0x0001
#define STUN_MESSAGE_BINDING_SUCCESS 0x0101
#define STUN_MESSAGE_COOKIE 0x2112a442

#define STUN_ATTRIBUTE_MAPPED_ADDRESS 0x0001
#define STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS 0x0020

typedef struct _STUN_MAPPED_IPV4_ADDRESS_ATTRIBUTE {
    USHORT attributeType;
    USHORT attributeLength;
    UCHAR reserved;
    UCHAR addressFamily;
    USHORT port;
    ULONG address;
} STUN_MAPPED_IPV4_ADDRESS_ATTRIBUTE, *PSTUN_MAPPED_IPV4_ADDRESS_ATTRIBUTE;

typedef struct _STUN_MESSAGE {
    USHORT messageType;
    USHORT messageLength;
    UINT magicCookie;
    UINT transactionId[3];
} STUN_MESSAGE, *PSTUN_MESSAGE;

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
    {IPPROTO_UDP, 48002, true},
    {IPPROTO_UDP, 48010, true}
};

char logFilePath[MAX_PATH + 1];

enum MessagePriority {
    MpInfo,
    MpWarn,
    MpError
};

void DisplayMessage(const char* message, MessagePriority priority = MpError, bool terminal = true)
{
    printf("%s\n", message);

    if (terminal) {
        printf("--------------- MISS LOG -------------------\n");

        char missPath[MAX_PATH + 1];
        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\miss-current.log", missPath, sizeof(missPath));
        FILE* f = fopen(missPath, "r");
        if (f != nullptr) {
            char buffer[1024];
            while (!feof(f)) {
                int bytesRead = fread(buffer, 1, ARRAYSIZE(buffer), f);
                fwrite(buffer, 1, bytesRead, stdout);
            }
            fclose(f);
        }
        else {
            printf("Failed to find MISS log\n");
        }

        fflush(stdout);
    }


    DWORD flags = MB_OK | MB_TOPMOST | MB_SETFOREGROUND;
    switch (priority) {
    case MpInfo:
        flags |= MB_ICONINFORMATION;
        break;
    case MpWarn:
        flags |= MB_ICONWARNING;
        break;
    case MpError:
        flags |= MB_ICONERROR;
        break;
    }
    MessageBoxA(nullptr, message, "Moonlight Internet Streaming Tester", flags);

    if (priority != MpInfo && terminal) {
        flags = MB_YESNO | MB_TOPMOST | MB_SETFOREGROUND | MB_ICONINFORMATION;
        switch (MessageBoxA(nullptr, "Would you like to view the troubleshooting log?",
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

bool IsGameStreamEnabled()
{
    DWORD error;
    DWORD enabled;
    DWORD len;
    HKEY key;

    error = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\NVIDIA Corporation\\NvStream", 0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (error != ERROR_SUCCESS) {
        printf("RegOpenKeyEx() failed: %d\n", error);
        DisplayMessage("GeForce Experience was not detected on this PC. Make sure you're installing this utility on your GeForce GameStream-compatible PC, not the device running Moonlight.");
        return false;
    }

    len = sizeof(enabled);
    error = RegQueryValueExA(key, "EnableStreaming", nullptr, nullptr, (LPBYTE)&enabled, &len);
    RegCloseKey(key);
    if (error != ERROR_SUCCESS || !enabled) {
        // GFE may not even write EnableStreaming until the user enables GameStream for the first time
        if (error != ERROR_SUCCESS) {
            printf("RegQueryValueExA() failed: %d\n", error);
        }
        DisplayMessage("GameStream is not enabled in GeForce Experience. Please open GeForce Experience settings, navigate to the Shield tab, and turn GameStream on.");
        return false;
    }
    else {
        printf("GeForce Experience installed and GameStream is enabled\n");
        return true;
    }
}

enum PortTestStatus {
    PortTestOk,
    PortTestError,
    PortTestUnknown
};
PortTestStatus TestPort(PSOCKADDR_STORAGE addr, int proto, int port, bool withServer)
{
    SOCKET clientSock = INVALID_SOCKET, serverSock = INVALID_SOCKET;
    int err;

    clientSock = socket(addr->ss_family, proto == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM, proto);
    if (clientSock == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return PortTestError;
    }

    if (withServer) {
        serverSock = socket(addr->ss_family, proto == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM, proto);
        if (serverSock == INVALID_SOCKET) {
            printf("socket() failed: %d\n", WSAGetLastError());
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
                // we can proceed if it's a TCP connection.
                if (proto == IPPROTO_TCP) {
                    closesocket(serverSock);
                    serverSock = INVALID_SOCKET;
                }
                else {
                    // We can't continue to test for UDP ports.
                    printf("Unknown (in use)\n");
                    closesocket(clientSock);
                    closesocket(serverSock);
                    return PortTestUnknown;
                }
            }
            else {
                printf("bind() failed: %d\n", WSAGetLastError());
                closesocket(clientSock);
                closesocket(serverSock);
                return PortTestError;
            }
        }

        if (proto == IPPROTO_TCP && serverSock != INVALID_SOCKET) {
            err = listen(serverSock, 1);
            if (err == SOCKET_ERROR) {
                printf("listen() failed: %d\n", WSAGetLastError());
                closesocket(clientSock);
                closesocket(serverSock);
                return PortTestError;
            }
        }
    }

    ULONG nbIo = 1;
    err = ioctlsocket(clientSock, FIONBIO, &nbIo);
    if (err == SOCKET_ERROR) {
        printf("ioctlsocket() failed: %d\n", WSAGetLastError());
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
    sin6.sin6_port = htons(port);

    if (proto == IPPROTO_TCP) {
        err = connect(clientSock, (struct sockaddr*)&sin6, addrLen);
        if (err == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
            printf("connect() failed: %d\n", WSAGetLastError());
        }
        else {
            struct timeval timeout = {};
            fd_set fds;

            FD_ZERO(&fds);
            FD_SET(clientSock, &fds);

            timeout.tv_sec = 3;
            err = select(0, nullptr, &fds, nullptr, &timeout);
            if (err == 1) {
                // Our FD was signalled for connect() completion
                printf("Success\n");
            }
            else if (err == 0) {
                // Timed out
                printf("Timeout\n");
            }
            else {
                printf("select() failed: %d\n", WSAGetLastError());
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
        err = sendto(clientSock, testMsg, sizeof(testMsg), 0, (struct sockaddr*)&sin6, addrLen);
        if (err == SOCKET_ERROR) {
            printf("sendto() failed: %d\n", WSAGetLastError());
            closesocket(clientSock);
            closesocket(serverSock);
            return PortTestError;
        }

        struct timeval timeout = {};
        fd_set fds;

        FD_ZERO(&fds);
        FD_SET(serverSock, &fds);

        timeout.tv_sec = 3;
        err = select(0, &fds, nullptr, nullptr, &timeout);
        if (err == 1) {
            // Our FD was signalled for data available
            printf("Success\n");
        }
        else if (err == 0) {
            // Timed out
            printf("Timeout\n");
        }
        else {
            printf("select() failed: %d\n", WSAGetLastError());
        }

        closesocket(clientSock);
        closesocket(serverSock);

        return err == 1 ? PortTestOk : PortTestError;
    }
}

bool TestAllPorts(PSOCKADDR_STORAGE addr, char* portMsg, int portMsgLen)
{
    bool ret = true;

    for (int i = 0; i < ARRAYSIZE(k_Ports); i++) {
        printf("Testing %s %d...",
            k_Ports[i].proto == IPPROTO_TCP ? "TCP" : "UDP",
            k_Ports[i].port);
        PortTestStatus status = TestPort(addr, k_Ports[i].proto, k_Ports[i].port, k_Ports[i].withServer);
        if (status != PortTestOk) {
            // If we got an unknown result, assume it matches with whatever
            // we've gotten so far.
            if (status == PortTestError || !ret) {
                int msgLen = snprintf(portMsg, portMsgLen, "%s %d\n",
                    k_Ports[i].proto == IPPROTO_TCP ? "TCP" : "UDP",
                    k_Ports[i].port);
                portMsg += msgLen;
                portMsgLen -= msgLen;

                // Keep going to check all ports and report the failing ones
                ret = false;
            }
        }
    }

    return ret;
}

bool FindLocalInterfaceIP4Address(PSOCKADDR_IN addr)
{
    SOCKET s;

    printf("Finding local IP address...");

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return false;
    }

    SOCKADDR_IN sin = {};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(443);
    sin.sin_addr.S_un.S_addr = inet_addr("8.8.8.8");
    int err = connect(s, (struct sockaddr*)&sin, sizeof(sin));
    if (err == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return false;
    }

    // Determine which local interface we bound to
    int nameLen = sizeof(*addr);
    err = getsockname(s, (struct sockaddr*)addr, &nameLen);
    if (err == SOCKET_ERROR) {
        printf("getsockname() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return false;
    }

    char addrStr[64];
    inet_ntop(AF_INET, &addr->sin_addr, addrStr, sizeof(addrStr));
    printf("%s\n", addrStr);

    return true;
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

    printf("Checking for UPnP port mapping for %s %s -> %s...", protoStr, portStr, myAddr);
    int err = UPNP_GetSpecificPortMappingEntry(
        urls->controlURL, data->first.servicetype, portStr, protoStr, nullptr,
        intClient, intPort, desc, enabled, leaseDuration);
    if (err == 714) {
        // NoSuchEntryInArray
        printf("NOT FOUND\n");
        return NOT_FOUND;
    }
    else if (err == UPNPCOMMAND_SUCCESS) {
        if (!strcmp(myAddr, intClient)) {
            printf("OK\n");
            return OK;
        }
        else {
            printf("CONFLICT - %s %s\n", desc, intClient);
            snprintf(conflictMessage, 128, "%s (%s)", desc, intClient);
            return CONFLICTED;
        }
    }
    else {
        printf("ERROR %d\n", err);
        return ERRORED;
    }
}

bool STUNFindWanAddress(PSOCKADDR_IN wanAddr)
{
    SOCKET s;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return false;
    }

    struct hostent *host;

    host = gethostbyname("stun.stunprotocol.org");
    if (host == nullptr) {
        printf("gethostbyname() failed\n");
        closesocket(s);
        return false;
    }

    SOCKADDR_IN sin = {};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(3478);
    sin.sin_addr = *(struct in_addr*)host->h_addr;
    int err = connect(s, (struct sockaddr*)&sin, sizeof(sin));
    if (err == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return false;
    }

    STUN_MESSAGE reqMsg;
    reqMsg.messageType = htons(STUN_MESSAGE_BINDING_REQUEST);
    reqMsg.messageLength = 0;
    reqMsg.magicCookie = htonl(STUN_MESSAGE_COOKIE);
    for (int i = 0; i < ARRAYSIZE(reqMsg.transactionId); i++) {
        rand_s(&reqMsg.transactionId[i]);
    }

    err = send(s, (char *)&reqMsg, sizeof(reqMsg), 0);
    if (err == SOCKET_ERROR) {
        printf("send() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return false;
    }

    union {
        struct {
            STUN_MESSAGE respMsg;
            STUN_MAPPED_IPV4_ADDRESS_ATTRIBUTE mappedAddress;
        };
        char respBuf[128];
    };

    int bytesRead = recv(s, respBuf, sizeof(respBuf), 0);
    if (bytesRead == SOCKET_ERROR) {
        printf("recv() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return false;
    }
    else if (bytesRead < sizeof(respMsg)) {
        printf("STUN message truncated: %d\n", bytesRead);
        closesocket(s);
        return false;
    }

    closesocket(s);

    if (htonl(respMsg.magicCookie) != STUN_MESSAGE_COOKIE) {
        printf("Bad STUN cookie value: %x\n", htonl(respMsg.magicCookie));
        return false;
    }
    else if (!RtlEqualMemory(reqMsg.transactionId, respMsg.transactionId, sizeof(reqMsg.transactionId))) {
        printf("STUN transaction ID mismatch\n");
        return false;
    }
    else if (htons(respMsg.messageType) != STUN_MESSAGE_BINDING_SUCCESS) {
        printf("STUN message type mismatch: %x\n", htons(respMsg.messageType));
        return false;
    }
    else if (bytesRead < sizeof(respMsg) + sizeof(mappedAddress)) {
        printf("STUN message too short: %d\n", bytesRead);
        return false;
    }
    else if (htons(mappedAddress.attributeType) != STUN_ATTRIBUTE_MAPPED_ADDRESS &&
        htons(mappedAddress.attributeType) != STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS) {
        printf("STUN attribute type mismatch: %x\n", htons(mappedAddress.attributeType));
        return false;
    }
    else if (htons(mappedAddress.attributeLength) != 8) {
        printf("STUN address length mismatch: %d\n", htons(mappedAddress.attributeLength));
        return false;
    }
    else if (mappedAddress.addressFamily != 1) {
        printf("STUN address family mismatch: %x\n", mappedAddress.addressFamily);
        return false;
    }

    if (htons(mappedAddress.attributeType) == STUN_ATTRIBUTE_MAPPED_ADDRESS) {
        // The address is directly encoded
        wanAddr->sin_addr.S_un.S_addr = mappedAddress.address;
    }
    else {
        // The address is XORed
        wanAddr->sin_addr.S_un.S_addr = mappedAddress.address ^ respMsg.magicCookie;
    }

    return true;
}

bool CheckWANAccess(PSOCKADDR_IN wanAddr, PSOCKADDR_IN reportedWanAddr, bool* foundPortForwardingRules, bool* igdDisconnected)
{
    natpmp_t natpmp;

    *foundPortForwardingRules = false;
    *igdDisconnected = false;

    bool gotReportedWanAddress = false;
    int natPmpErr = initnatpmp(&natpmp, 0, 0);
    if (natPmpErr != 0) {
        printf("initnatpmp() failed: %d\n", natPmpErr);
    }
    else {
        natPmpErr = sendpublicaddressrequest(&natpmp);
        if (natPmpErr < 0) {
            printf("sendpublicaddressrequest() failed: %d\n", natPmpErr);
            closenatpmp(&natpmp);
        }
    }

    {
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
                if (ret == 2) {
                    *igdDisconnected = true;
                }
                printf("Discovered UPnP IGD at: %s\n", urls.controlURL);
                printf("Detecting WAN IP address via UPnP...");
                ret = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, wanAddrStr);
                if (ret == UPNPCOMMAND_SUCCESS && strlen(wanAddrStr) > 0) {
                    reportedWanAddr->sin_addr.S_un.S_addr = wanAddr->sin_addr.S_un.S_addr = inet_addr(wanAddrStr);
                    printf("%s\n", wanAddrStr);

                    if (wanAddr->sin_addr.S_un.S_addr != 0) {
                        gotReportedWanAddress = true;
                    }
                }
                else {
                    printf("FAILED %d\n", ret);
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
                            "Remove that PC from your network or uninstall the Moonlight Internet Streaming Service from it, then restart your router.",
                            conflictEntry);
                        DisplayMessage(conflictMessage);
                        return false;
                    default:
                        continue;
                    }
                }
            }
            else {
                printf("No UPnP IGD detected\n");
            }

            FreeUPNPUrls(&urls);
        }
        else {
            printf("No UPnP devices detected\n");
        }
    }

    // Use the delay of upnpDiscoverAll() to also allow the NAT-PMP endpoint time to respond
    if (natPmpErr >= 0) {
        printf("Detecting WAN IP address via NAT-PMP...");

        natpmpresp_t response;
        natPmpErr = readnatpmpresponseorretry(&natpmp, &response);
        closenatpmp(&natpmp);

        if (natPmpErr == 0) {
            char addrStr[64];
            reportedWanAddr->sin_addr = wanAddr->sin_addr = response.pnu.publicaddress.addr;
            inet_ntop(AF_INET, &response.pnu.publicaddress.addr, addrStr, sizeof(addrStr));
            printf("%s\n", addrStr);
            if (wanAddr->sin_addr.S_un.S_addr != 0) {
                gotReportedWanAddress = true;
            }
        }
        else {
            printf("FAILED %d\n", natPmpErr);
        }
    }

    printf("Detecting WAN IP address via STUN...");
    if (!STUNFindWanAddress(wanAddr)) {
        if (!gotReportedWanAddress) {
            DisplayMessage("Unable to determine your public IP address. Please check your Internet connection.");
            return false;
        }
    }
    else {
        char addrStr[64];
        inet_ntop(AF_INET, &wanAddr->sin_addr, addrStr, sizeof(addrStr));
        printf("%s\n", addrStr);

        if (!gotReportedWanAddress) {
            // If we didn't get anything from UPnP or NAT-PMP, just populate the reported
            // address with what we got from STUN
            *reportedWanAddr = *wanAddr;
        }
    }

    return true;
}

bool IsPossibleCGN(PSOCKADDR_IN wanAddr)
{
    DWORD addr = htonl(wanAddr->sin_addr.S_un.S_addr);

    // 10.0.0.0/8 - ISPs used to use this
    if ((addr & 0xFF000000) == 0x0A000000) {
        return true;
    }
    // 100.64.0.0/10 - RFC6598 official CGN address
    else if ((addr & 0xFFC0) == 0x64400000) {
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

    char tempPath[MAX_PATH + 1];
    GetTempPathA(sizeof(tempPath), tempPath);

    snprintf(logFilePath, sizeof(logFilePath), "%s\\%s", tempPath, "mis-test.log");
    freopen(logFilePath, "w", stdout);

    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != NO_ERROR) {
        DisplayMessage("Unable to initialize WinSock");
        return err;
    }

    fprintf(stderr, "Checking if GameStream is enabled...\n");

    // First check if GameStream is enabled
    if (!IsGameStreamEnabled()) {
        return -1;
    }

    union {
        SOCKADDR_STORAGE ss;
        SOCKADDR_IN sin;
        SOCKADDR_IN6 sin6;
    };
    char msgBuf[2048];
    char portMsgBuf[512];

    fprintf(stderr, "Testing local GameStream connectivity...\n");

    // Try to connect via IPv4 loopback
    ss = {};
    sin.sin_family = AF_INET;
    sin.sin_addr = in4addr_loopback;
    printf("Testing GameStream ports via loopback\n");
    if (!TestAllPorts(&ss, portMsgBuf, sizeof(portMsgBuf))) {
        snprintf(msgBuf, sizeof(msgBuf),
            "Local GameStream connectivity check failed. Please try reinstalling GeForce Experience.\n\nThe following ports were not working:\n%s",
            portMsgBuf);
        DisplayMessage(msgBuf);
        return -1;
    }

    if (!FindLocalInterfaceIP4Address(&sin)) {
        DisplayMessage("Unable to perform GameStream connectivity check. Please check your Internet connection and try again.");
        return -1;
    }

    fprintf(stderr, "Testing network GameStream connectivity...\n");

    // Try to connect via LAN IPv4 address
    printf("Testing GameStream ports via local network\n");
    if (!TestAllPorts(&ss, portMsgBuf, sizeof(portMsgBuf))) {
        snprintf(msgBuf, sizeof(msgBuf),
            "Local network GameStream connectivity check failed. Try temporarily disabling your firewall software or adding firewall exceptions for the following ports:\n%s",
            portMsgBuf);
        DisplayMessage(msgBuf);
        return -1;
    }

    fprintf(stderr, "Detecting public IP address...\n");

    bool upnpRulesFound, igdDisconnected;
    SOCKADDR_IN locallyReportedWanAddr;
    if (!CheckWANAccess(&sin, &locallyReportedWanAddr, &upnpRulesFound, &igdDisconnected)) {
        return -1;
    }

    if (igdDisconnected) {
        DisplayMessage("Your router reports to be disconnected from the Internet. Make sure UPnP is enabled in your router settings. "
            "If this message persists, make sure your router isn't connected to the Internet through another router. If it is, switch one of the routers to bridge/AP mode.\n\n"
            "Just in case this warning is due to a buggy router, the test will continue anyway.", MpWarn, false);
    }

    // Detect a double NAT by detecting STUN and and UPnP mismatches
    if (sin.sin_addr.S_un.S_addr != locallyReportedWanAddr.sin_addr.S_un.S_addr) {
        printf("Testing GameStream ports via UPnP/NAT-PMP reported WAN address\n");

        // We don't actually care about the outcome here but it's nice to have in logs
        // to determine whether solving the double NAT will actually make Moonlight work.
        TestAllPorts((PSOCKADDR_STORAGE)&locallyReportedWanAddr, portMsgBuf, sizeof(portMsgBuf));

        printf("Detected inconsistency between UPnP/NAT-PMP and STUN reported WAN addresses!\n");
    }

    fprintf(stderr, "Testing Internet GameStream connectivity...\n");

    char wanAddrStr[64];
    inet_ntop(AF_INET, &sin.sin_addr, wanAddrStr, sizeof(wanAddrStr));

    // Try to connect via WAN IPv4 address
    printf("Testing GameStream ports via STUN-reported WAN address\n");
    if (!TestAllPorts(&ss, portMsgBuf, sizeof(portMsgBuf))) {
        if (IsDoubleNAT(&locallyReportedWanAddr)) {
            snprintf(msgBuf, sizeof(msgBuf), "Your router appears be connected to the Internet through another router. This configuration breaks port forwarding. To resolve this, switch one of the routers into bridge/AP mode.");
            DisplayMessage(msgBuf);
        }
        else if (IsPossibleCGN(&locallyReportedWanAddr)) {
            snprintf(msgBuf, sizeof(msgBuf), "Your ISP is running a Carrier-Grade NAT that is preventing you from hosting services like Moonlight on the Internet. Contact your ISP and ask for a dedicated public IP address.");
            DisplayMessage(msgBuf);
        }
        else if (igdDisconnected) {
            snprintf(msgBuf, sizeof(msgBuf), "Internet GameStream connectivity check failed. Make sure UPnP is enabled in your router settings and that you don't have two devices acting as routers connected together.");
            DisplayMessage(msgBuf);
        }
        else if (upnpRulesFound) {
            snprintf(msgBuf, sizeof(msgBuf), "We found the correct UPnP rules, but we couldn't confirm that they are working. You can try streaming from a different network by typing the following address into Moonlight's Add PC dialog: %s\n\n"
                "If that doesn't work, check your router settings for any existing Moonlight port forwarding entries and delete them.", wanAddrStr);
            DisplayMessage(msgBuf, MpWarn);
        }
        else {
            snprintf(msgBuf, sizeof(msgBuf), "Internet GameStream connectivity check failed. Make sure UPnP is enabled in your router settings.\n\nThe following ports were not forwarded properly:\n%s", portMsgBuf);
            DisplayMessage(msgBuf);
        }
        return -1;
    }

    snprintf(msgBuf, sizeof(msgBuf), "All tests passed! You should be able to stream by typing the following address into Moonlight's Add PC dialog: %s", wanAddrStr);
    DisplayMessage(msgBuf, MpInfo);

    return 0;
}