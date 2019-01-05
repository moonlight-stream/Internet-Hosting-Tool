#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <stdio.h>
#include <stdlib.h>

#define MINIUPNP_STATICLIB
#include <miniupnpc/miniupnpc.h>

static const char* k_SsdpSearchFormatString =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: %s:1900\r\n"
    "ST: ssdp:all\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 5\r\n"
    "\r\n";

// Based on logic in https://github.com/miniupnp/miniupnp/blob/master/miniupnpc/minissdpc.c
static void
parseReply(const char* reply, int size,
           const char** location, int *locationsize,
           const char** st, int* stsize,
           const char** usn, int* usnsize)
{
    int lineStartIdx = 0;
    int headerEndIdx = 0;
    for (int i = 0; i < size; i++) {
        switch (reply[i])
        {
        case ':':
            // Stop parsing the header at the first colon, but ignore subsequent colons
            if (headerEndIdx == 0) {
                headerEndIdx = i;
            }
            break;
        case '\r':
        case '\n':
            if (headerEndIdx != 0) {
                // Skip the colon and spaces
                do { headerEndIdx++; } while (reply[headerEndIdx] == ' ');

                // Check if it's one of the values we care about
                if (!_strnicmp(reply + lineStartIdx, "location:", 9)) {
                    *location = reply + headerEndIdx;
                    *locationsize = i - headerEndIdx;
                }
                else if (!_strnicmp(reply + lineStartIdx, "st:", 3)) {
                    *st = reply + headerEndIdx;
                    *stsize = i - headerEndIdx;
                }
                else if (!_strnicmp(reply + lineStartIdx, "usn:", 4)) {
                    *usn = reply + headerEndIdx;
                    *usnsize = i - headerEndIdx;
                }

                // Move on to the next header value
                headerEndIdx = 0;
            }
            lineStartIdx = i + 1;
            break;
        default:
            break;
        }
    }
}

struct UPNPDev* getUPnPDevicesByAddress(IN_ADDR address)
{
    SOCKET s;
    SOCKADDR_IN connAddr;
    char searchBuffer[512];
    int chars;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return nullptr;
    }

    connAddr = {};
    connAddr.sin_family = AF_INET;
    connAddr.sin_port = htons(1900);
    connAddr.sin_addr = address;

    // Use connect() to ensure we don't get responses from other devices
    if (connect(s, (struct sockaddr*)&connAddr, sizeof(connAddr)) == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return nullptr;
    }

    // We will be reading all responses at the end, so ensure we have ample buffer space
    // to allow responses to accumulate without loss.
    int recvBufferSize = 65535;
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&recvBufferSize, sizeof(recvBufferSize)) == SOCKET_ERROR) {
        printf("setsockopt() failed: %d\n", WSAGetLastError());
    }

    // Send the first search message with HOST set properly
    chars = snprintf(searchBuffer, ARRAYSIZE(searchBuffer), k_SsdpSearchFormatString, inet_ntoa(address));
    if (send(s, searchBuffer, chars, 0) == SOCKET_ERROR) {
        printf("send() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return nullptr;
    }

    // Send another search message with HOST set to 239.255.255.250 to avoid issues
    // on routers that explicitly check for that HOST value
    chars = snprintf(searchBuffer, ARRAYSIZE(searchBuffer), k_SsdpSearchFormatString, "239.255.255.250");
    if (send(s, searchBuffer, chars, 0) == SOCKET_ERROR) {
        printf("send() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return nullptr;
    }

    Sleep(5000);

    // Switch to non-blocking mode to read the responses
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    char responseBuffer[2048];
    struct UPNPDev* deviceList = nullptr;
    for (;;) {
        int bytesRead = recv(s, responseBuffer, sizeof(responseBuffer) - 1, 0);
        if (bytesRead == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEMSGSIZE) {
                // Skip packets larger than our buffer
                printf("recv() message too large\n");
                continue;
            }
            else if (WSAGetLastError() != WSAEWOULDBLOCK) {
                printf("recv() failed: %d\n", WSAGetLastError());
            }
            break;
        }

        // Null-terminate the buffer
        responseBuffer[bytesRead] = 0;

        // Parse the first status line:
        // HTTP/1.1 200 OK
        char* protocol = strtok(responseBuffer, " ");
        char* statusCodeStr = strtok(nullptr, " ");
        char* statusMessage = strtok(nullptr, "\r");

        // Check for a valid response header
        if (protocol == nullptr) {
            printf("Missing protocol in SSDP header\n");
            continue;
        }
        else if (statusCodeStr == nullptr) {
            printf("Missing status code in SSDP header\n");
            continue;
        }
        // FIXME: Should we require statusMessage too?
        else if (_stricmp(protocol, "HTTP/1.0") && _stricmp(protocol, "HTTP/1.1")) {
            printf("Unexpected protocol: %s\n", protocol);
            continue;
        }
        else if (atoi(statusCodeStr) != 200) {
            printf("Unexpected status: %s %s\n", statusCodeStr, statusMessage);
            continue;
        }

        // Parse the header options
        char* remainder = strtok(nullptr, "");
        const char* loc = nullptr;
        const char* st = nullptr;
        const char* usn = ""; // Initialize to empty since it's optional
        int locSize = 0;
        int stSize = 0;
        int usnSize = 0;
        parseReply(remainder, strlen(remainder),
            &loc, &locSize, &st, &stSize, &usn, &usnSize);

        if (!loc || locSize == 0 || !st || stSize == 0) {
            printf("Required value missing: %d %d\n", locSize, stSize);
            continue;
        }

        struct UPNPDev* newDev = (struct UPNPDev*)malloc(sizeof(*newDev) + usnSize + locSize + stSize + 3);

        newDev->pNext = deviceList;

        newDev->usn = &newDev->buffer[0];
        memcpy(newDev->usn, usn, usnSize);
        newDev->usn[usnSize] = 0;

        newDev->descURL = newDev->usn + usnSize + 1;
        memcpy(newDev->descURL, loc, locSize);
        newDev->descURL[locSize] = 0;

        newDev->st = newDev->descURL + locSize + 1;
        memcpy(newDev->st, st, stSize);
        newDev->st[stSize] = 0;

        newDev->scope_id = 0; // IPv6 only

        deviceList = newDev;
    }

    closesocket(s);

    return deviceList;
}

// Start at TTL 2 to skip contacting our default gateway
#define TTL_START 2

bool getHopsIP4(IN_ADDR* hopAddress, int* hopAddressCount)
{
    HANDLE icmpFile;
    struct hostent* host;
    const char* requestBuffer = "Test";
    union {
        ICMP_ECHO_REPLY replies[ANYSIZE_ARRAY];
        char replyBuffer[128];
    };

    host = gethostbyname("moonlight-stream.org");
    if (host == nullptr) {
        printf("gethostbyname() failed: %d\n", WSAGetLastError());
        return false;
    }

    icmpFile = IcmpCreateFile();
    if (icmpFile == INVALID_HANDLE_VALUE) {
        printf("IcmpCreateFile() failed: %d\n", GetLastError());
        return false;
    }

    int ttl;
    for (ttl = TTL_START; ttl - TTL_START < *hopAddressCount; ttl++)
    {
        IP_OPTION_INFORMATION ipOptions;

        ipOptions.Ttl = ttl;
        ipOptions.Tos = 0;
        ipOptions.Flags = 0;
        ipOptions.OptionsSize = 0;

        DWORD replyCount = IcmpSendEcho(icmpFile,
            *(IPAddr*)host->h_addr,
            (LPVOID)requestBuffer, sizeof(requestBuffer),
            &ipOptions,
            replyBuffer, sizeof(replyBuffer),
            3000);
        if (replyCount == 0) {
            printf("IcmpSendEcho() failed: %d\n", GetLastError());
            break;
        }
        else if (replyCount != 1) {
            printf("Got extra replies: %d\n", replyCount);
            break;
        }

        if (replies[0].Status == IP_TTL_EXPIRED_TRANSIT) {
            // Get the IP address that responded to us
            printf("Hop %d: %s\n", ttl - TTL_START, inet_ntoa(*(IN_ADDR*)&replies[0].Address));
            hopAddress[ttl - TTL_START] = *(IN_ADDR*)&replies[0].Address;
        }
        else {
            // Bail on anything else
            printf("Hop %d: %s (error %d)\n", ttl - TTL_START, inet_ntoa(*(IN_ADDR*)&replies[0].Address), replies[0].Status);
            break;
        }
    }

    IcmpCloseHandle(icmpFile);

    *hopAddressCount = ttl - TTL_START;
    return true;
}

