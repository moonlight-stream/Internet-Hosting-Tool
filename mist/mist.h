#pragma once

#define _CRT_RAND_S
#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
#include <WinSock2.h>

#include "..\version.h"

#define CONSOLE_OUT stdout
#define LOG_OUT stderr

bool getExternalAddressPortIP4(unsigned short localPort, PSOCKADDR_IN wanAddr);