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
    USHORT nboPort = htons(tuple->port);
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
        if (RtlEqualMemory(&sourceAddr.sin_addr, &in4addr_loopback, sizeof(sourceAddr.sin_addr)) && sourceAddr.sin_port == nboPort) {
            // Traffic incoming from loopback interface - send it to the last remote address
            destinationAddr = lastRemoteAddr;
        }
        else {
            // Traffic incoming from the remote host - remember the source
            lastRemoteAddr = sourceAddr;

            // Send it to the normal port via the loopback adapter
            destinationAddr = sourceAddr;
            destinationAddr.sin_addr = in4addr_loopback;
            destinationAddr.sin_port = nboPort;
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
    int error;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        error = WSAGetLastError();
        printf("socket() failed: %d\n", error);
        return error;
    }

    // Bind to the alternate port
    RtlZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(Port + RELAY_PORT_OFFSET);
    if (bind(sock, (PSOCKADDR)&addr, sizeof(addr)) == SOCKET_ERROR) {
        error = WSAGetLastError();
        printf("bind() failed: %d\n", error);
        closesocket(sock);
        return error;
    }

    tuple = (PUDP_TUPLE)malloc(sizeof(*tuple));
    if (tuple == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    tuple->socket = sock;
    tuple->port = Port;

    thread = CreateThread(NULL, 0, UdpRelayThreadProc, tuple, 0, NULL);
    if (thread == NULL) {
        error = GetLastError();
        printf("CreateThread() failed: %d\n", error);
        closesocket(sock);
        return error;
    }

    CloseHandle(thread);

    return 0;
}