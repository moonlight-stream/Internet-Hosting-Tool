#define _CRT_SECURE_NO_WARNINGS

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "..\version.h"

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

#define NL "\n"

#define SERVICE_NAME "MISS"
#define UPNP_SERVICE_NAME "Moonlight"
#define POLLING_DELAY_SEC 120
#define PORT_MAPPING_DURATION_SEC 3600
#define UPNP_DISCOVERY_DELAY_MS 5000

static struct port_entry {
    int proto;
    int port;
} k_Ports[] = {
    {IPPROTO_TCP, 47984},
    {IPPROTO_TCP, 47989},
    {IPPROTO_TCP, 48010},
    {IPPROTO_UDP, 47998},
    {IPPROTO_UDP, 47999},
    {IPPROTO_UDP, 48000},
    {IPPROTO_UDP, 48002},
    {IPPROTO_UDP, 48010}
};

void UPnPCreatePinholeForPort(struct UPNPUrls* urls, struct IGDdatas* data, int proto, const char* myAddr, int port)
{
    char uniqueId[8];
    char protoStr[3];
    char portStr[6];

    snprintf(portStr, sizeof(portStr), "%d", port);
    snprintf(protoStr, sizeof(protoStr), "%d", proto);

    printf("Creating UPnP IPv6 pinhole for %s %s -> %s...", protoStr, portStr, myAddr);

    // Lease time is in seconds - 7200 = 2 hours
    int err = UPNP_AddPinhole(urls->controlURL_6FC, data->IPv6FC.servicetype, "empty", portStr, myAddr, portStr, protoStr, "7200", uniqueId);
    if (err == UPNPCOMMAND_SUCCESS) {
        printf("OK" NL);
    }
    else {
        printf("ERROR %d (%s)" NL, err, strupnperror(err));
    }
}

bool UPnPMapPort(struct UPNPUrls* urls, struct IGDdatas* data, int proto, const char* myAddr, int port, bool enable)
{
    char intClient[16];
    char intPort[6];
    char desc[80];
    char enabled[4];
    char leaseDuration[16];
    const char* protoStr;
    char portStr[6];
    char myDesc[80];
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];

    DWORD nameLen = sizeof(computerName);
    if (!GetComputerNameA(computerName, &nameLen)) {
        printf("GetComputerNameA() failed: %d", GetLastError());
        snprintf(computerName, sizeof(computerName), "UNKNOWN");
    }
    snprintf(myDesc, sizeof(myDesc), "%s - %s", UPNP_SERVICE_NAME, computerName);

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
        return false;
    }

    printf("Checking for existing UPnP port mapping for %s %s -> %s...", protoStr, portStr, myAddr);
    int err = UPNP_GetSpecificPortMappingEntry(
        urls->controlURL, data->first.servicetype, portStr, protoStr, nullptr,
        intClient, intPort, desc, enabled, leaseDuration);
    if (err == 714) {
        // NoSuchEntryInArray
        printf("NOT FOUND" NL);
    }
    else if (err == UPNPCOMMAND_SUCCESS) {
        if (!strcmp(intClient, myAddr) && !strcmp(desc, myDesc)) {
            if (atoi(leaseDuration) == 0) {
                printf("OK (Permanent)" NL);
            }
            else {
                printf("OK (%s seconds remaining)" NL, leaseDuration);
            }

            if (!enable) {
                // This is our entry. Go ahead and nuke it
                printf("Deleting UPnP mapping for %s %s -> %s...", protoStr, portStr, myAddr);
                err = UPNP_DeletePortMapping(urls->controlURL, data->first.servicetype, portStr, protoStr, nullptr);
                if (err == UPNPCOMMAND_SUCCESS) {
                    printf("OK" NL);
                }
                else {
                    printf("ERROR %d" NL, err);
                }

                return true;
            }
        }
        else {
            printf("CONFLICT: %s %s" NL, intClient, desc);

            // Some UPnP IGDs won't let unauthenticated clients delete other conflicting port mappings
            // for security reasons, but we will give it a try anyway.
            printf("Trying to delete conflicting UPnP mapping for %s %s -> %s...", protoStr, portStr, intClient);
            err = UPNP_DeletePortMapping(urls->controlURL, data->first.servicetype, portStr, protoStr, nullptr);
            if (err == UPNPCOMMAND_SUCCESS) {
                printf("OK" NL);
            }
            else if (err == 606) {
                printf("UNAUTHORIZED" NL);
                return false;
            }
            else {
                printf("ERROR %d" NL, err);
                return false;
            }
        }
    }
    else {
        printf("ERROR %d (%s)" NL, err, strupnperror(err));
    }

    // Bail if GameStream is disabled
    if (!enable) {
        return true;
    }

    // Create or update the expiration time of an existing mapping
    snprintf(leaseDuration, sizeof(leaseDuration), "%d", PORT_MAPPING_DURATION_SEC);
    printf("Updating UPnP port mapping for %s %s -> %s...", protoStr, portStr, myAddr);
    err = UPNP_AddPortMapping(
        urls->controlURL, data->first.servicetype, portStr,
        portStr, myAddr, myDesc, protoStr, nullptr, leaseDuration);
    if (err == 725) { // OnlyPermanentLeasesSupported
        err = UPNP_AddPortMapping(
            urls->controlURL, data->first.servicetype, portStr,
            portStr, myAddr, myDesc, protoStr, nullptr, "0");
        printf("PERMANENT ");
    }
    if (err == UPNPCOMMAND_SUCCESS) {
        printf("OK" NL);
        return true;
    }
    else {
        printf("ERROR %d (%s)" NL, err, strupnperror(err));
        return false;
    }
}

bool ResolveStableIP6Address(char* tmpAddr)
{
    union {
        IP_ADAPTER_ADDRESSES addresses;
        char buffer[8192];
    };
    ULONG error;
    ULONG length;
    PIP_ADAPTER_ADDRESSES currentAdapter;
    PIP_ADAPTER_UNICAST_ADDRESS currentAddress;
    in6_addr targetAddress;

    inet_pton(AF_INET6, tmpAddr, &targetAddress);

    // Get a list of all interfaces with IPv6 addresses on the system
    length = sizeof(buffer);
    error = GetAdaptersAddresses(AF_INET6,
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME,
        NULL,
        &addresses,
        &length);
    if (error != ERROR_SUCCESS) {
        printf("GetAdaptersAddresses() failed: %d" NL, error);
        return false;
    }

    currentAdapter = &addresses;
    currentAddress = nullptr;
    while (currentAdapter != nullptr) {
        // First, search for the adapter
        currentAddress = currentAdapter->FirstUnicastAddress;
        while (currentAddress != nullptr) {
            assert(currentAddress->Address.lpSockaddr->sa_family == AF_INET6);

            PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;

            if (RtlEqualMemory(&currentAddrV6->sin6_addr, &targetAddress, sizeof(targetAddress))) {
                // Found interface with matching address
                break;
            }

            currentAddress = currentAddress->Next;
        }

        if (currentAddress != nullptr) {
            // Get out of the loop if we found the matching address
            break;
        }

        currentAdapter = currentAdapter->Next;
    }

    if (currentAdapter == nullptr) {
        printf("No adapter found with IPv6 address: %s" NL, tmpAddr);
        return false;
    }

    // Now currentAdapter is the adapter we reached the IGD with. Find a suitable
    // public address that we can use to create the pinhole.
    currentAddress = currentAdapter->FirstUnicastAddress;
    while (currentAddress != nullptr) {
        assert(currentAddress->Address.lpSockaddr->sa_family == AF_INET6);

        PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;

        // Exclude temporary addresses and link-local addresses
        if (currentAddress->SuffixOrigin != IpSuffixOriginRandom && currentAddrV6->sin6_scope_id == 0) {
            break;
        }

        currentAddress = currentAddress->Next;
    }

    if (currentAddress == nullptr) {
        printf("No suitable alternate address found for %s" NL, tmpAddr);
        return false;
    }

    PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;
    inet_ntop(AF_INET6, &currentAddrV6->sin6_addr, tmpAddr, 128);

    return true;
}

bool UPnPHandleDeviceList(struct UPNPDev* list, bool ipv6, bool enable)
{
    struct UPNPUrls urls;
    struct IGDdatas data;
    char myAddr[128];
    char wanAddr[128];
    int pinholeAllowed = false;
    bool success = true;

    int ret = UPNP_GetValidIGD(list, &urls, &data, myAddr, sizeof(myAddr));
    if (ret == 0) {
        printf("No UPnP device found!" NL);
        return false;
    }
    else if (ret == 3) {
        printf("No UPnP IGD found!" NL);
        FreeUPNPUrls(&urls);
        return false;
    }
    else if (ret == 1) {
        printf("Found a connected UPnP IGD" NL);
    }
    else if (ret == 2) {
        printf("Found a disconnected UPnP IGD (!)" NL);

        // Even if we are able to add forwarding entries, go ahead and try NAT-PMP
        success = false;
    }
    else {
        printf("UPNP_GetValidIGD() failed: %d" NL, ret);
        return false;
    }

    if (ipv6) {
        // Convert what is likely a IPv6 temporary address into
        // the stable IPv6 address for the same interface.
        if (ResolveStableIP6Address(myAddr)) {
            printf("Stable global IPv6 address is: %s" NL, myAddr);

            if (data.IPv6FC.controlurl[0] == 0) {
                printf("IPv6 firewall control not supported by UPnP IGD!" NL);
                return false;
            }

            int firewallEnabled;
            ret = UPNP_GetFirewallStatus(urls.controlURL_6FC, data.IPv6FC.servicetype, &firewallEnabled, &pinholeAllowed);
            if (ret == UPNPCOMMAND_SUCCESS) {
                printf("UPnP IPv6 firewall control available. Firewall is %s, pinhole is %s" NL,
                    firewallEnabled ? "enabled" : "disabled",
                    pinholeAllowed ? "allowed" : "disallowed");
            }
            else {
                printf("UPnP IPv6 firewall control is unavailable with error %d (%s)" NL, ret, strupnperror(ret));
                pinholeAllowed = false;
            }
        }
    }
    else {
        ret = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, wanAddr);
        if (ret == UPNPCOMMAND_SUCCESS) {
            printf("UPnP IGD WAN address is: %s" NL, wanAddr);
        }
    }

    for (int i = 0; i < ARRAYSIZE(k_Ports); i++) {
        if (!ipv6) {
            if (!UPnPMapPort(&urls, &data, k_Ports[i].proto, myAddr, k_Ports[i].port, enable)) {
                success = false;
            }
        }
        if (pinholeAllowed) {
            UPnPCreatePinholeForPort(&urls, &data, k_Ports[i].proto, myAddr, k_Ports[i].port);
        }
    }

    FreeUPNPUrls(&urls);
    return success;
}

bool NATPMPMapPort(natpmp_t* natpmp, int proto, int port, bool enable)
{
    int natPmpProto;

    switch (proto)
    {
    case IPPROTO_TCP:
        natPmpProto = NATPMP_PROTOCOL_TCP;
        break;
    case IPPROTO_UDP:
        natPmpProto = NATPMP_PROTOCOL_UDP;
        break;
    default:
        assert(false);
        return false;
    }

    printf("Updating NAT-PMP port mapping for %s %d...", proto == IPPROTO_TCP ? "TCP" : "UDP", port);
    int err = sendnewportmappingrequest(natpmp, natPmpProto, port, enable ? port : 0, enable ? PORT_MAPPING_DURATION_SEC : 0);
    if (err < 0) {
        printf("ERROR %d" NL, err);
        return false;
    }

    natpmpresp_t response;
    do
    {
        fd_set fds;
        struct timeval timeout;

        FD_ZERO(&fds);
        FD_SET(natpmp->s, &fds);

        err = getnatpmprequesttimeout(natpmp, &timeout);
        if (err != 0) {
            assert(err == 0);
            printf("WAIT FAILED: %d" NL, err);
            return false;
        }

        select(0, &fds, nullptr, nullptr, &timeout);

        err = readnatpmpresponseorretry(natpmp, &response);
    } while (err == NATPMP_TRYAGAIN);

    if (err != 0) {
        printf("FAILED %d" NL, err);
        return false;
    }
    else if (response.pnu.newportmapping.lifetime == 0 && !enable) {
        printf("DELETED" NL);
        return true;
    }
    else if (response.pnu.newportmapping.mappedpublicport != port) {
        printf("CONFLICT" NL);

        // Some buggy routers (Untangle) will change the *internal* port when
        // adjusting a port mapping request that collides. This is why we also
        // pass privateport back from the response and not from the port we originally
        // asked for. Warn in this case.
        if (response.pnu.newportmapping.privateport != port) {
            printf("Buggy router changed the internal port when handling NAT-PMP conflict! (%d -> %d)" NL,
                port, response.pnu.newportmapping.privateport);
        }

        // It couldn't assign us the external port we requested and gave us an alternate external port.
        // We can't use this alternate mapping, so immediately release it.
        printf("Deleting unwanted NAT-PMP mapping %s %d...", proto == IPPROTO_TCP ? "TCP" : "UDP", response.pnu.newportmapping.mappedpublicport);
        err = sendnewportmappingrequest(natpmp, natPmpProto, response.pnu.newportmapping.privateport, 0, 0);
        if (err < 0) {
            printf("ERROR %d" NL, err);
            return false;
        }
        else {
            do {
                fd_set fds;
                struct timeval timeout;

                FD_ZERO(&fds);
                FD_SET(natpmp->s, &fds);

                err = getnatpmprequesttimeout(natpmp, &timeout);
                if (err != 0) {
                    assert(err == 0);
                    printf("WAIT FAILED: %d" NL, err);
                    return false;
                }

                select(0, &fds, nullptr, nullptr, &timeout);

                err = readnatpmpresponseorretry(natpmp, &response);
            } while (err == NATPMP_TRYAGAIN);

            if (err == 0) {
                printf("DONE" NL);
                return false;
            }
            else {
                printf("FAILED %d" NL, err);
                return false;
            }
        }
    }
    else {
        printf("OK (%d seconds remaining)" NL, response.pnu.newportmapping.lifetime);
        return true;
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
        return false;
    }

    len = sizeof(enabled);
    error = RegQueryValueExA(key, "EnableStreaming", nullptr, nullptr, (LPBYTE)&enabled, &len);
    RegCloseKey(key);
    if (error != ERROR_SUCCESS) {
        printf("RegQueryValueExA() failed: %d" NL, error);
        return false;
    }
    else if (!enabled) {
        printf("GameStream is OFF!" NL);
        return false;
    }
    else {
        printf("GameStream is ON!" NL);
        return true;
    }
}

void UpdatePortMappings(bool enable)
{
    natpmp_t natpmp;
    bool tryNatPmp = true;

    printf("Starting port mapping update..." NL);

    int natPmpErr = initnatpmp(&natpmp, 0, 0);
    if (natPmpErr != 0) {
        printf("initnatpmp() failed: %d" NL, natPmpErr);
    }
    else {
        natPmpErr = sendpublicaddressrequest(&natpmp);
        if (natPmpErr < 0) {
            printf("sendpublicaddressrequest() failed: %d" NL, natPmpErr);
            closenatpmp(&natpmp);
        }
    }

    fflush(stdout);

    {
        int upnpErr;
        struct UPNPDev* ipv4Devs = upnpDiscoverAll(UPNP_DISCOVERY_DELAY_MS, nullptr, nullptr, UPNP_LOCAL_PORT_ANY, 0, 2, &upnpErr);

        printf("UPnP IPv4 IGD discovery completed with error code: %d" NL, upnpErr);

        // Use the delay of upnpDiscoverAll() to also allow the NAT-PMP endpoint time to respond
        if (natPmpErr >= 0) {
            natpmpresp_t response;
            natPmpErr = readnatpmpresponseorretry(&natpmp, &response);
            if (natPmpErr == 0) {
                char addrStr[64];
                inet_ntop(AF_INET, &response.pnu.publicaddress.addr, addrStr, sizeof(addrStr));
                printf("NAT-PMP WAN address is: %s" NL, addrStr);
            }
            else {
                printf("NAT-PMP public address request failed: %d" NL, natPmpErr);
                closenatpmp(&natpmp);
            }
        }

        // Don't try NAT-PMP if UPnP succeeds
        if (UPnPHandleDeviceList(ipv4Devs, false, enable)) {
            printf("UPnP IPv4 port mapping successful" NL);
            if (enable) {
                // We still want to try NAT-PMP if we're removing
                // rules to ensure any NAT-PMP rules get cleaned up
                tryNatPmp = false;
            }
        }

        freeUPNPDevlist(ipv4Devs);
    }

    fflush(stdout);

    {
        int upnpErr;
        struct UPNPDev* ipv6Devs = upnpDiscoverAll(UPNP_DISCOVERY_DELAY_MS, nullptr, nullptr, UPNP_LOCAL_PORT_ANY, 1, 2, &upnpErr);

        printf("UPnP IPv6 IGD discovery completed with error code: %d" NL, upnpErr);

        // Ignore whether IPv6 succeeded when decided to use NAT-PMP
        UPnPHandleDeviceList(ipv6Devs, true, enable);

        freeUPNPDevlist(ipv6Devs);
    }

    fflush(stdout);

    if (natPmpErr == 0) {
        if (tryNatPmp) {
            bool success = true;
            for (int i = 0; i < ARRAYSIZE(k_Ports); i++) {
                if (!NATPMPMapPort(&natpmp, k_Ports[i].proto, k_Ports[i].port, enable)) {
                    success = false;
                }
            }
            if (success) {
                printf("NAT-PMP IPv4 port mapping successful" NL);
            }
        }

        closenatpmp(&natpmp);
    }

    fflush(stdout);
}

void NETIOAPI_API_ IpInterfaceChangeNotificationCallback(PVOID context, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE)
{
    SetEvent((HANDLE)context);
}

void ResetLogFile()
{
    char oldLogFilePath[MAX_PATH + 1];
    char currentLogFilePath[MAX_PATH + 1];

    ExpandEnvironmentStringsA("%ProgramData%\\MISS\\miss-old.log", oldLogFilePath, sizeof(oldLogFilePath));
    ExpandEnvironmentStringsA("%ProgramData%\\MISS\\miss-current.log", currentLogFilePath, sizeof(currentLogFilePath));

    // Delete the old log file
    DeleteFileA(oldLogFilePath);

    // Rotate the current to the old log file
    MoveFileA(currentLogFilePath, oldLogFilePath);

    // Redirect stdout to this new file
    freopen(currentLogFilePath, "w", stdout);

    // Print a log header
    printf("Moonlight Internet Streaming Service v" VER_VERSION_STR NL);
}

DWORD WINAPI GameStreamStateChangeThread(PVOID Context)
{
    HKEY key;

    // We're watching this key that way we can still detect GameStream turning on
    // if GFE wasn't even installed when our service started
    DWORD err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\NVIDIA Corporation", 0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (err != ERROR_SUCCESS) {
        printf("RegOpenKeyExA() failed: %d" NL, err);
        return err;
    }

    // Notify the main thread when the GameStream state changes
    bool lastGameStreamState = IsGameStreamEnabled();
    while ((err = RegNotifyChangeKeyValue(key, true, REG_NOTIFY_CHANGE_LAST_SET, nullptr, false)) == ERROR_SUCCESS) {
        bool currentGameStreamState = IsGameStreamEnabled();
        if (lastGameStreamState != currentGameStreamState) {
            SetEvent((HANDLE)Context);
        }
        lastGameStreamState = currentGameStreamState;
    }

    printf("RegNotifyChangeKeyValue() failed: %d" NL, err);
    return err;
}

int Run()
{
    HANDLE ifaceChangeEvent = CreateEvent(nullptr, true, false, nullptr);
    HANDLE gsChangeEvent = CreateEvent(nullptr, true, false, nullptr);
    HANDLE events[2] = { ifaceChangeEvent, gsChangeEvent };

    ResetLogFile();

    // Create the thread to watch for GameStream state changes
    CreateThread(nullptr, 0, GameStreamStateChangeThread, gsChangeEvent, 0, nullptr);

    // Watch for IP address and interface changes
    HANDLE ifaceChangeHandle;
    NotifyIpInterfaceChange(AF_UNSPEC, IpInterfaceChangeNotificationCallback, ifaceChangeEvent, false, &ifaceChangeHandle);

    for (;;) {
        ResetEvent(gsChangeEvent);
        ResetEvent(ifaceChangeEvent);
        UpdatePortMappings(IsGameStreamEnabled());

        // Refresh when half the duration is expired or if an IP interface
        // change event occurs.
        printf("Going to sleep..." NL);
        fflush(stdout);

        ULONGLONG beforeSleepTime = GetTickCount64();
        DWORD ret = WaitForMultipleObjects(ARRAYSIZE(events), events, false, POLLING_DELAY_SEC * 1000);
        if (ret == WAIT_OBJECT_0) {
            ResetLogFile();

            printf("Woke up for interface change notification after %lld seconds" NL,
                (GetTickCount64() - beforeSleepTime) / 1000);

            // Wait a little bit for the interface to settle down (DHCP, RA, etc)
            Sleep(10000);
        }
        else if (ret == WAIT_OBJECT_0 + 1) {
            ResetLogFile();

            printf("Woke up for GameStream state change notification after %lld seconds" NL,
                (GetTickCount64() - beforeSleepTime) / 1000);
        }
        else {
            ResetLogFile();

            printf("Woke up for periodic refresh" NL);
        }
    }
}

static SERVICE_STATUS_HANDLE ServiceStatusHandle;
static SERVICE_STATUS ServiceStatus;

DWORD
WINAPI
HandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    switch (dwControl)
    {
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    case SERVICE_CONTROL_STOP:
        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        ServiceStatus.dwControlsAccepted = 0;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

        printf("Removing UPnP/NAT-PMP rules after service stop request\n");
        UpdatePortMappings(false);

        printf("The service is stopping\n");
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        return NO_ERROR;

    default:
        return NO_ERROR;
    }
}

VOID
WINAPI
ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
    int err;

    ServiceStatusHandle = RegisterServiceCtrlHandlerEx(SERVICE_NAME, HandlerEx, NULL);
    if (ServiceStatusHandle == NULL) {
        fprintf(stderr, "RegisterServiceCtrlHandlerEx() failed: %d" NL, GetLastError());
        return;
    }

    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwWin32ExitCode = NO_ERROR;
    ServiceStatus.dwWaitHint = 0;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    ServiceStatus.dwCheckPoint = 0;

    // Tell SCM we're running
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

    // Start the service
    err = Run();
    if (err != 0) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        ServiceStatus.dwWin32ExitCode = err;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        return;
    }
}

static const SERVICE_TABLE_ENTRY ServiceTable[] = {
    { (LPSTR)SERVICE_NAME, ServiceMain },
    { NULL, NULL }
};

int main(int argc, char* argv[])
{
    WSADATA wsaData;
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != NO_ERROR) {
        return err;
    }

    if (argc == 2 && !strcmp(argv[1], "exe")) {
        Run();
        return 0;
    }

    return StartServiceCtrlDispatcher(ServiceTable);
}