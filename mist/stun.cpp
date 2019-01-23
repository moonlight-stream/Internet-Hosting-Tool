#define _CRT_RAND_S
#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>
#include <WinSock2.h>

#include <stdio.h>

#define STUN_PORT 3478

#define STUN_RECV_TIMEOUT_SEC 3

#define STUN_MESSAGE_BINDING_REQUEST 0x0001
#define STUN_MESSAGE_BINDING_SUCCESS 0x0101
#define STUN_MESSAGE_COOKIE 0x2112a442

#define STUN_ATTRIBUTE_MAPPED_ADDRESS 0x0001
#define STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS 0x0020

#pragma pack(push, 1)

typedef struct _STUN_ATTRIBUTE_HEADER {
    unsigned short type;
    unsigned short length;
} STUN_ATTRIBUTE_HEADER, *PSTUN_ATTRIBUTE_HEADER;

typedef struct _STUN_MAPPED_IPV4_ADDRESS_ATTRIBUTE {
    STUN_ATTRIBUTE_HEADER hdr;
    unsigned char reserved;
    unsigned char addressFamily;
    unsigned short port;
    unsigned int address;
} STUN_MAPPED_IPV4_ADDRESS_ATTRIBUTE, *PSTUN_MAPPED_IPV4_ADDRESS_ATTRIBUTE;

#define TXID_DWORDS 3
typedef struct _STUN_MESSAGE {
    unsigned short messageType;
    unsigned short messageLength;
    unsigned int magicCookie;
    int transactionId[TXID_DWORDS];
} STUN_MESSAGE, *PSTUN_MESSAGE;

#pragma pack(pop)

bool getExternalAddressPortIP4(int proto, unsigned short localPort, PSOCKADDR_IN wanAddr)
{
    SOCKET sock;
    STUN_MESSAGE reqMsg;
    int i;
    int bytesRead;
    int tries;
    int timeout;
    PSTUN_ATTRIBUTE_HEADER attribute;
    PSTUN_MAPPED_IPV4_ADDRESS_ATTRIBUTE ipv4Attrib;
    struct hostent *host;
    union {
        STUN_MESSAGE hdr;
        char buf[1024];
    } resp;

    host = gethostbyname("stun.moonlight-stream.org");
    if (host == nullptr) {
        printf("gethostbyname() failed: %d\n", WSAGetLastError());
        return false;
    }

    sock = socket(AF_INET, proto == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM, proto);
    if (sock == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return false;
    }

    struct sockaddr_in bindAddr = {};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(localPort);
    if (bind(sock, (struct sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        return false;
    }

    reqMsg.messageType = htons(STUN_MESSAGE_BINDING_REQUEST);
    reqMsg.messageLength = 0;
    reqMsg.magicCookie = htonl(STUN_MESSAGE_COOKIE);
    for (i = 0; i < TXID_DWORDS; i++) {
        reqMsg.transactionId[i] = rand();
    }

    SOCKADDR_IN stunAddr = {};
    stunAddr.sin_family = AF_INET;
    stunAddr.sin_port = htons(STUN_PORT);
    stunAddr.sin_addr = *(struct in_addr*)host->h_addr;

    // We'll connect() even for UDP so we can use send()/recv() and share more code
    if (connect(sock, (struct sockaddr*)&stunAddr, sizeof(stunAddr)) == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        return false;
    }

    // For UDP, we'll do 3 iterations of 1 second each. For TCP,
    // we'll do one iteration with a 3 second wait.
    if (proto == IPPROTO_TCP) {
        tries = 1;
        timeout = STUN_RECV_TIMEOUT_SEC;
    }
    else {
        tries = STUN_RECV_TIMEOUT_SEC;
        timeout = 1;
    }

    bytesRead = 0;
    for (i = 0; i < tries; i++) {
        // Retransmit the request every second until the timeout elapses
        if (send(sock, (char *)&reqMsg, sizeof(reqMsg), 0) == SOCKET_ERROR) {
            printf("send() failed: %d\n", WSAGetLastError());
            closesocket(sock);
            return false;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;

        int selectRes = select(0, &fds, nullptr, nullptr, &tv);
        if (selectRes == 0) {
            // Timeout - continue looping
            continue;
        }
        else if (selectRes == SOCKET_ERROR) {
            printf("select() failed: %d\n", WSAGetLastError());
            closesocket(sock);
            return false;
        }

        // Error handling is below
        bytesRead = recv(sock, resp.buf, sizeof(resp.buf), 0);
        break;
    }

    closesocket(sock);

    if (bytesRead == 0) {
        printf("No response from STUN server\n");
        return false;
    }
    else if (bytesRead == SOCKET_ERROR) {
        printf("Failed to read STUN binding response: %d\n", WSAGetLastError());
        return false;
    }
    else if (bytesRead < sizeof(resp.hdr)) {
        printf("STUN message truncated: %d\n", bytesRead);
        return false;
    }
    else if (htonl(resp.hdr.magicCookie) != STUN_MESSAGE_COOKIE) {
        printf("Bad STUN cookie value: %x\n", htonl(resp.hdr.magicCookie));
        return false;
    }
    else if (memcmp(reqMsg.transactionId, resp.hdr.transactionId, sizeof(reqMsg.transactionId))) {
        printf("STUN transaction ID mismatch\n");
        return false;
    }
    else if (htons(resp.hdr.messageType) != STUN_MESSAGE_BINDING_SUCCESS) {
        printf("STUN message type mismatch: %x\n", htons(resp.hdr.messageType));
        return false;
    }

    attribute = (PSTUN_ATTRIBUTE_HEADER)(&resp.hdr + 1);
    bytesRead -= sizeof(resp.hdr);
    while (bytesRead > sizeof(*attribute)) {
        if (bytesRead < sizeof(*attribute) + htons(attribute->length)) {
            printf("STUN attribute out of bounds: %d\n", htons(attribute->length));
            return false;
        }
        // Mask off the comprehension bit
        else if ((htons(attribute->type) & 0x7FFF) != STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS) {
            // Continue searching if this wasn't our address
            bytesRead -= sizeof(*attribute) + htons(attribute->length);
            attribute = (PSTUN_ATTRIBUTE_HEADER)(((char*)attribute) + sizeof(*attribute) + htons(attribute->length));
            continue;
        }

        ipv4Attrib = (PSTUN_MAPPED_IPV4_ADDRESS_ATTRIBUTE)attribute;
        if (htons(ipv4Attrib->hdr.length) != 8) {
            printf("STUN address length mismatch: %d\n", htons(ipv4Attrib->hdr.length));
            return false;
        }
        else if (ipv4Attrib->addressFamily != 1) {
            printf("STUN address family mismatch: %x\n", ipv4Attrib->addressFamily);
            return false;
        }

        *wanAddr = {};
        wanAddr->sin_family = AF_INET;

        // The address and port are XORed with the cookie
        wanAddr->sin_port = ipv4Attrib->port ^ (short)resp.hdr.magicCookie;
        wanAddr->sin_addr.S_un.S_addr = ipv4Attrib->address ^ resp.hdr.magicCookie;

        return true;
    }

    printf("No XOR mapped address found in STUN response!\n");
    return false;
}