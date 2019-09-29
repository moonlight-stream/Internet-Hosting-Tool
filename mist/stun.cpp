#include "mist.h"

#include <stdio.h>

#define STUN_PORT 3478

#define STUN_RECV_TIMEOUT_SEC 5

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

bool getExternalAddressPortIP4(unsigned short localPort, PSOCKADDR_IN wanAddr)
{
    SOCKET sock;
    STUN_MESSAGE reqMsg;
    int i;
    int bytesRead;
    int tries;
    int timeout;
    int err;
    PSTUN_ATTRIBUTE_HEADER attribute;
    PSTUN_MAPPED_IPV4_ADDRESS_ATTRIBUTE ipv4Attrib;
    struct addrinfo* result;
    struct addrinfo hints;
    union {
        STUN_MESSAGE hdr;
        char buf[1024];
    } resp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    err = getaddrinfo("stun.moonlight-stream.org", "3478", &hints, &result);
    if (err != 0 || result == NULL) {
        fprintf(LOG_OUT, "getaddrinfo() failed: %d\n", err);
        return false;
    }

    sock = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
    if (sock == INVALID_SOCKET) {
        fprintf(LOG_OUT, "socket() failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        return false;
    }

    struct sockaddr_in bindAddr = {};
    bindAddr.sin_family = hints.ai_family;
    bindAddr.sin_port = htons(localPort);
    if (bind(sock, (struct sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
        fprintf(LOG_OUT, "bind() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        freeaddrinfo(result);
        return false;
    }

    reqMsg.messageType = htons(STUN_MESSAGE_BINDING_REQUEST);
    reqMsg.messageLength = 0;
    reqMsg.magicCookie = htonl(STUN_MESSAGE_COOKIE);
    for (i = 0; i < TXID_DWORDS; i++) {
        reqMsg.transactionId[i] = rand();
    }

    bytesRead = 0;
    for (i = 0; i < STUN_RECV_TIMEOUT_SEC; i++) {
        // Retransmit the request every second to all resolved IP addresses until the timeout elapses
        for (struct addrinfo* current = result; current != NULL; current = current->ai_next) {
            if (sendto(sock, (char*)&reqMsg, sizeof(reqMsg), 0, current->ai_addr, current->ai_addrlen) == SOCKET_ERROR) {
                fprintf(LOG_OUT, "sendto() failed: %d\n", WSAGetLastError());
            }
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int selectRes = select(0, &fds, nullptr, nullptr, &tv);
        if (selectRes == 0) {
            // Timeout - continue looping
            continue;
        }
        else if (selectRes == SOCKET_ERROR) {
            fprintf(LOG_OUT, "select() failed: %d\n", WSAGetLastError());
            closesocket(sock);
            freeaddrinfo(result);
            return false;
        }

        // Error handling is below
        bytesRead = recvfrom(sock, resp.buf, sizeof(resp.buf), 0, NULL, NULL);
        break;
    }

    freeaddrinfo(result);
    closesocket(sock);

    if (bytesRead == 0) {
        fprintf(LOG_OUT, "No response from STUN server\n");
        return false;
    }
    else if (bytesRead == SOCKET_ERROR) {
        fprintf(LOG_OUT, "Failed to read STUN binding response: %d\n", WSAGetLastError());
        return false;
    }
    else if (bytesRead < sizeof(resp.hdr)) {
        fprintf(LOG_OUT, "STUN message truncated: %d\n", bytesRead);
        return false;
    }
    else if (htonl(resp.hdr.magicCookie) != STUN_MESSAGE_COOKIE) {
        fprintf(LOG_OUT, "Bad STUN cookie value: %x\n", htonl(resp.hdr.magicCookie));
        return false;
    }
    else if (memcmp(reqMsg.transactionId, resp.hdr.transactionId, sizeof(reqMsg.transactionId))) {
        fprintf(LOG_OUT, "STUN transaction ID mismatch\n");
        return false;
    }
    else if (htons(resp.hdr.messageType) != STUN_MESSAGE_BINDING_SUCCESS) {
        fprintf(LOG_OUT, "STUN message type mismatch: %x\n", htons(resp.hdr.messageType));
        return false;
    }

    attribute = (PSTUN_ATTRIBUTE_HEADER)(&resp.hdr + 1);
    bytesRead -= sizeof(resp.hdr);
    while (bytesRead > sizeof(*attribute)) {
        if (bytesRead < sizeof(*attribute) + htons(attribute->length)) {
            fprintf(LOG_OUT, "STUN attribute out of bounds: %d\n", htons(attribute->length));
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
            fprintf(LOG_OUT, "STUN address length mismatch: %d\n", htons(ipv4Attrib->hdr.length));
            return false;
        }
        else if (ipv4Attrib->addressFamily != 1) {
            fprintf(LOG_OUT, "STUN address family mismatch: %x\n", ipv4Attrib->addressFamily);
            return false;
        }

        *wanAddr = {};
        wanAddr->sin_family = AF_INET;

        // The address and port are XORed with the cookie
        wanAddr->sin_port = ipv4Attrib->port ^ (short)resp.hdr.magicCookie;
        wanAddr->sin_addr.S_un.S_addr = ipv4Attrib->address ^ resp.hdr.magicCookie;

        return true;
    }

    fprintf(LOG_OUT, "No XOR mapped address found in STUN response!\n");
    return false;
}