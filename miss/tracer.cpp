#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <stdio.h>

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
            *hopAddressCount = ttl - 1;
            break;
        }
    }

    IcmpCloseHandle(icmpFile);

    return true;
}