#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>

#include <WinSock2.h>
#include <Ws2ipdef.h>

#include "relay.h"

typedef struct _UDP_TUPLE {
    SOCKET socket;
    unsigned short port;
} UDP_TUPLE, *PUDP_TUPLE;

DWORD
WINAPI
UdpRelayThreadProc(LPVOID Context)
{
    PUDP_TUPLE tuple = (PUDP_TUPLE)Context;
    SOCKADDR_IN lastRemoteAddr;

    // Ensure the relay threads aren't preempted by games or other CPU intensive activity
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    RtlZeroMemory(&lastRemoteAddr, sizeof(lastRemoteAddr));

    for (;;) {
        char buffer[4096];
        SOCKADDR_IN sourceAddr;
        int sourceAddrLen;
        int recvLen;

        sourceAddrLen = sizeof(sourceAddr);
        recvLen = recvfrom(tuple->socket, buffer, sizeof(buffer), 0, (PSOCKADDR)&sourceAddr, &sourceAddrLen);
        if (recvLen == SOCKET_ERROR) {
            continue;
        }
        
        SOCKADDR_IN destinationAddr;
        if (RtlEqualMemory(&sourceAddr.sin_addr, &in4addr_loopback, sizeof(sourceAddr.sin_addr))) {
            // Traffic incoming from loopback interface - send it to the last remote address
            destinationAddr = lastRemoteAddr;
        }
        else {
            // Traffic incoming from the remote host - remember the source
            lastRemoteAddr = sourceAddr;

            // Send it to the normal port via the loopback adapter
            destinationAddr = sourceAddr;
            destinationAddr.sin_addr = in4addr_loopback;
            destinationAddr.sin_port = htons(tuple->port);
        }

        sendto(tuple->socket, buffer, recvLen, 0, (PSOCKADDR)&destinationAddr, sizeof(destinationAddr));
    }

    closesocket(tuple->socket);
    free(tuple);
    return 0;
}

int StartUdpRelay(unsigned short Port)
{
    SOCKET sock;
    SOCKADDR_IN addr;
    HANDLE thread;
    PUDP_TUPLE tuple;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return WSAGetLastError();
    }

    // Bind to the alternate port
    RtlZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(Port + RELAY_PORT_OFFSET);
    if (bind(sock, (PSOCKADDR)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        return WSAGetLastError();
    }

    tuple = (PUDP_TUPLE)malloc(sizeof(*tuple));
    if (tuple == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    tuple->socket = sock;
    tuple->port = Port;

    thread = CreateThread(NULL, 0, UdpRelayThreadProc, tuple, 0, NULL);
    if (thread == NULL) {
        printf("CreateThread() failed: %d\n", GetLastError());
        closesocket(sock);
        return GetLastError();
    }

    CloseHandle(thread);

    return 0;
}