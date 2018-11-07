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

    char responseBuffer[1024];
    struct UPNPDev* deviceList = nullptr;
    for (;;) {
        int bytesRead = recv(s, responseBuffer, sizeof(responseBuffer) - 1, 0);
        if (bytesRead == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
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
        if (_stricmp(protocol, "HTTP/1.0") && _stricmp(protocol, "HTTP/1.1")) {
            printf("Unexpected protocol: %s\n", protocol);
            continue;
        }
        if (atoi(statusCodeStr) != 200) {
            printf("Unexpected status: %s %s\n", statusCodeStr, statusMessage);
            continue;
        }

        // Parse the header options
        // SERVER: FreeBSD/11.2-RELEASE-p2 UPnP/1.1 MiniUPnPd/2.0\r\n
        char* location = nullptr;
        char* st = nullptr;
        while (char* headerName = strtok(nullptr, "\r\n:")) {
            char* headerValue = strtok(nullptr, "\r");

            // Skip leading spaces
            while (*headerValue == ' ') headerValue++;

            if (!_stricmp(headerName, "LOCATION")) {
                location = headerValue;
            }
            else if (!_stricmp(headerName, "ST")) {
                st = headerValue;
            }
        }

        if (!location || location[0] == 0 || !st || st[0] == 0) {
            printf("Required value missing: \"%s\" \"%s\"\n", location, st);
            continue;
        }

        struct UPNPDev* newDev = (struct UPNPDev*)malloc(sizeof(*newDev) + strlen(location) + strlen(st) + 2);
        
        newDev->pNext = deviceList;
        newDev->usn = &newDev->buffer[0]; newDev->buffer[0] = 0;
        newDev->descURL = strcpy(newDev->usn + strlen(newDev->usn) + 1, location);
        newDev->st = strcpy(newDev->descURL + strlen(newDev->descURL) + 1, st);
        newDev->scope_id = 0; // IPv6 only

        deviceList = newDev;
    }

    return deviceList;
}

bool getHopsIP4(IN_ADDR* hopAddress, int* hopAddressCount)
{
    HANDLE icmpFile;
    struct hostent* host;
    const char* requestBuffer = "Test";
    union {
        ICMP_ECHO_REPLY replies[ANYSIZE_ARRAY];
        char replyBuffer[128];
    };

    host = gethostbyname("google.com");
    if (host == nullptr) {
        printf("gethostbyname() failed: %d\n", WSAGetLastError());
        return false;
    }

    icmpFile = IcmpCreateFile();
    if (icmpFile == INVALID_HANDLE_VALUE) {
        printf("IcmpCreateFile() failed: %d\n", GetLastError());
        return false;
    }

    int ttl = 1;
    for (; ttl < *hopAddressCount; ttl++)
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
            printf("Hop %d: %s\n", ttl, inet_ntoa(*(IN_ADDR*)&replies[0].Address));
            hopAddress[ttl - 1] = *(IN_ADDR*)&replies[0].Address;
        }
        else {
            // Bail on anything else
            printf("Hop %d: %s (error %d)\n", ttl, inet_ntoa(*(IN_ADDR*)&replies[0].Address), replies[0].Status);
            break;
        }
    }

    IcmpCloseHandle(icmpFile);

    *hopAddressCount = ttl - 1;
    return true;
}

