#pragma once

#define _CRT_RAND_S
#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>
#include <WinSock2.h>

#include "..\version.h"

#define CONSOLE_OUT stderr
#define LOG_OUT stdout

bool getExternalAddressPortIP4(int proto, unsigned short localPort, PSOCKADDR_IN wanAddr);