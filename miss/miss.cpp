#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "relay.h"
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

bool getHopsIP4(IN_ADDR* hopAddress, int* hopAddressCount);
struct UPNPDev* getUPnPDevicesByAddress(IN_ADDR address);
bool PCPMapPort(PSOCKADDR_STORAGE localAddr, int localAddrLen, PSOCKADDR_STORAGE pcpAddr, int pcpAddrLen, int proto, int port, bool enable, bool indefinite);

#define SERVICE_NAME "MISS"
#define UPNP_SERVICE_NAME "Moonlight"
#define POLLING_DELAY_SEC 120
#define PORT_MAPPING_DURATION_SEC 3600
#define UPNP_DISCOVERY_DELAY_MS 5000
#define GAA_INITIAL_SIZE 8192

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

static const int k_WolPorts[] = { 9, 47009 };

static HANDLE s_StopEvent;
static CRITICAL_SECTION s_PortMappingUpdateLock;

bool UPnPMapPort(struct UPNPUrls* urls, struct IGDdatas* data, int proto, const char* myAddr, int port, bool enable, bool indefinite, bool validationPass)
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

    printf("Checking for existing UPnP port mapping for %s %s -> %s %s...", protoStr, portStr, myAddr, computerName);
    int err = UPNP_GetSpecificPortMappingEntry(
        urls->controlURL, data->first.servicetype, portStr, protoStr, nullptr,
        intClient, intPort, desc, enabled, leaseDuration);
    if (err == 714) {
        // NoSuchEntryInArray
        printf("NOT FOUND\n");

        if (validationPass) {
            // On validation, we found a missing entry. Convert this entry to indefinite
            // to see if it will stick.
            indefinite = true;
        }
    }
    else if (err == 606) {
        printf("UNAUTHORIZED\n");

        // If we're just validating, we're done. We can't know if the entry was
        // actually applied but we'll return true to avoid false errors if it was.
        if (validationPass) {
            return true;
        }
    }
    else if (err == UPNPCOMMAND_SUCCESS) {
        // Some routers change the description, so we can't check that here
        if (!strcmp(intClient, myAddr)) {
            if (atoi(leaseDuration) == 0) {
                printf("OK (Static, Internal port: %s)\n", intPort);

                // If we have an existing permanent mapping, we can just leave it alone.
                if (enable) {
                    return true;
                }
            }
            else {
                printf("OK (%s seconds remaining, Internal port: %s)\n", leaseDuration, intPort);
            }

            // If we're just validating, we found an entry, so we're done.
            if (validationPass) {
                return true;
            }

            if (!enable) {
                // This is our entry. Go ahead and nuke it
                printf("Deleting UPnP mapping for %s %s -> %s...", protoStr, portStr, myAddr);
                err = UPNP_DeletePortMapping(urls->controlURL, data->first.servicetype, portStr, protoStr, nullptr);
                if (err == UPNPCOMMAND_SUCCESS) {
                    printf("OK\n");
                }
                else {
                    printf("ERROR %d\n", err);
                }

                return true;
            }
        }
        else {
            printf("CONFLICT: %s %s\n", intClient, desc);

            // If we're just validating, we found an entry, so we're done.
            if (validationPass) {
                return true;
            }

            // Some UPnP IGDs won't let unauthenticated clients delete other conflicting port mappings
            // for security reasons, but we will give it a try anyway. If GameStream is not enabled,
            // we will leave the conflicting entry alone to avoid disturbing another PC's port forwarding
            // (especially if we're double NATed).
            if (enable) {
                printf("Trying to delete conflicting UPnP mapping for %s %s -> %s...", protoStr, portStr, intClient);
                err = UPNP_DeletePortMapping(urls->controlURL, data->first.servicetype, portStr, protoStr, nullptr);
                if (err == UPNPCOMMAND_SUCCESS) {
                    printf("OK\n");
                }
                else if (err == 606) {
                    printf("UNAUTHORIZED\n");
                    return false;
                }
                else {
                    printf("ERROR %d\n", err);
                    return false;
                }
            }
        }
    }
    else {
        printf("ERROR %d (%s)\n", err, strupnperror(err));

        // If we get a strange error from the router, we'll assume it's some old broken IGDv1
        // device and only use indefinite lease durations to hopefully avoid confusing it.
        indefinite = true;
    }

    // Bail if GameStream is disabled
    if (!enable) {
        return true;
    }

    // Create or update the expiration time of an existing mapping
    snprintf(leaseDuration, sizeof(leaseDuration), "%d",
        indefinite ? 0 : PORT_MAPPING_DURATION_SEC);
    printf("Updating UPnP port mapping for %s %s -> %s...", protoStr, portStr, myAddr);
    err = UPNP_AddPortMapping(
        urls->controlURL, data->first.servicetype, portStr,
        portStr, myAddr, myDesc, protoStr, nullptr, leaseDuration);
    if (err != UPNPCOMMAND_SUCCESS && !indefinite) {
        // This may be a broken IGD that doesn't like non-static mappings. Try a static
        // mapping before finally giving up.
        err = UPNP_AddPortMapping(
            urls->controlURL, data->first.servicetype, portStr,
            portStr, myAddr, myDesc, protoStr, nullptr, "0");
        printf("STATIC RETRY ");
    }
    else if (indefinite) {
        printf("STATIC ");
    }
    if (err == 718 && proto == IPPROTO_UDP && port >= 47000) { // ConflictInMappingEntry
        // Some UPnP implementations incorrectly deduplicate on the internal port instead
        // of the external port, in violation of the UPnP IGD specification. Since GFE creates
        // mappings on the same internal port as us, those routers break our mappings. To
        // work around this issue, we run relays for each of the UDP ports on an alternate
        // internal port. We'll try the alternate port if we get a conflict for a UDP entry.
        // Given that these are already horribly non-spec compliant, we won't take any chances
        // and we'll use an indefinite mapping too.
        char altPortStr[6];
        snprintf(altPortStr, sizeof(altPortStr), "%d", port + RELAY_PORT_OFFSET);
        err = UPNP_AddPortMapping(
            urls->controlURL, data->first.servicetype, portStr,
            altPortStr, myAddr, myDesc, protoStr, nullptr, "0");
        printf("ALTERNATE ");
    }
    if (err == UPNPCOMMAND_SUCCESS) {
        printf("OK\n");
        return true;
    }
    else {
        printf("ERROR %d (%s)\n", err, strupnperror(err));
        return false;
    }
}

bool GetIP4OnLinkPrefixLength(char* lanAddressString, int* prefixLength)
{
    PIP_ADAPTER_ADDRESSES addresses;
    ULONG error;
    ULONG length;
    PIP_ADAPTER_ADDRESSES currentAdapter;
    PIP_ADAPTER_UNICAST_ADDRESS currentAddress;
    in_addr targetAddress;

    inet_pton(AF_INET, lanAddressString, &targetAddress);

    addresses = NULL;
    length = GAA_INITIAL_SIZE;
    do {
        free(addresses);
        addresses = (PIP_ADAPTER_ADDRESSES)malloc(length);
        if (addresses == NULL) {
            printf("malloc(%u) failed\n", length);
            return false;
        }

        // Get a list of all interfaces with IPv4 addresses on the system
        error = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_SKIP_ANYCAST |
            GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_DNS_SERVER |
            GAA_FLAG_SKIP_FRIENDLY_NAME,
            NULL,
            addresses,
            &length);
    } while (error == ERROR_BUFFER_OVERFLOW);

    if (error != ERROR_SUCCESS) {
        printf("GetAdaptersAddresses() failed: %d\n", error);
        free(addresses);
        return false;
    }

    currentAdapter = addresses;
    currentAddress = nullptr;
    while (currentAdapter != nullptr) {
        currentAddress = currentAdapter->FirstUnicastAddress;
        while (currentAddress != nullptr) {
            assert(currentAddress->Address.lpSockaddr->sa_family == AF_INET);

            PSOCKADDR_IN currentAddrV4 = (PSOCKADDR_IN)currentAddress->Address.lpSockaddr;

            if (RtlEqualMemory(&currentAddrV4->sin_addr, &targetAddress, sizeof(targetAddress))) {
                *prefixLength = currentAddress->OnLinkPrefixLength;
                free(addresses);
                return true;
            }

            currentAddress = currentAddress->Next;
        }

        currentAdapter = currentAdapter->Next;
    }

    printf("No adapter found with IPv4 address: %s\n", lanAddressString);
    free(addresses);
    return false;
}

bool UPnPHandleDeviceList(struct UPNPDev* list, bool enable, char* lanAddrOverride, char* wanAddr)
{
    struct UPNPUrls urls;
    struct IGDdatas data;
    char localAddress[128];
    char* portMappingInternalAddress;
    int pinholeAllowed = false;
    bool success = true;

    int ret = UPNP_GetValidIGD(list, &urls, &data, localAddress, sizeof(localAddress));
    if (ret == 0) {
        printf("No UPnP device found!\n");
        return false;
    }
    else if (ret == 3) {
        printf("No UPnP IGD found!\n");
        FreeUPNPUrls(&urls);
        return false;
    }
    else if (ret == 1) {
        printf("Found a connected UPnP IGD (%s)\n", urls.rootdescURL);
    }
    else if (ret == 2) {
        printf("Found a disconnected (!) UPnP IGD (%s)\n", urls.rootdescURL);

        // Even if we are able to add forwarding entries, go ahead and try NAT-PMP
        success = false;
    }
    else {
        printf("UPNP_GetValidIGD() failed: %d\n", ret);
        return false;
    }

    ret = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, wanAddr);
    if (ret == UPNPCOMMAND_SUCCESS) {
        printf("UPnP IGD WAN address is: %s\n", wanAddr);
    }
    else {
        // Empty string
        *wanAddr = 0;
    }

    // We may be mapping on behalf of another device
    if (lanAddrOverride != nullptr) {
        portMappingInternalAddress = lanAddrOverride;
    }
    else {
        portMappingInternalAddress = localAddress;
    }

    // Create the port mappings
    for (int i = 0; i < ARRAYSIZE(k_Ports); i++) {
        if (!UPnPMapPort(&urls, &data, k_Ports[i].proto, portMappingInternalAddress, k_Ports[i].port, enable, false, false)) {
            success = false;
        }
    }

    // Do a best-effort for IPv4 Wake-on-LAN broadcast mappings
    for (int i = 0; i < ARRAYSIZE(k_WolPorts); i++) {
        if (lanAddrOverride == nullptr) {
            // Map the port to the broadcast address (may not work on all routers). This
            // ensures delivery even after the ARP entry for this PC times out on the router.
            int onLinkPrefixLen;
            if (GetIP4OnLinkPrefixLength(localAddress, &onLinkPrefixLen)) {
                int netmask = 0;
                for (int j = 0; j < onLinkPrefixLen; j++) {
                    netmask |= (1 << j);
                }

                in_addr broadcastAddr;
                broadcastAddr.S_un.S_addr = inet_addr(localAddress);
                broadcastAddr.S_un.S_addr |= ~netmask;

                char broadcastAddrStr[128];
                inet_ntop(AF_INET, &broadcastAddr, broadcastAddrStr, sizeof(broadcastAddrStr));

                UPnPMapPort(&urls, &data, IPPROTO_UDP, broadcastAddrStr, k_WolPorts[i], enable, true, false);
            }
        }
        else {
            // When we're mapping the WOL ports upstream of our router, we map directly to
            // the port on the upstream address (likely our router's WAN interface).
            UPnPMapPort(&urls, &data, IPPROTO_UDP, lanAddrOverride, k_WolPorts[i], enable, true, false);
        }
    }

    // Validate the rules are present and correct if they claimed to be added successfully
    if (success && enable) {
        // Wait 10 seconds for the router state to quiesce or the stop event to be set
        printf("Waiting before UPnP port validation...");
        if (WaitForSingleObject(s_StopEvent, 10000) == WAIT_TIMEOUT) {
            printf("done\n");

            // Perform the validation pass (converting any now missing entries to permanent ones)
            for (int i = 0; i < ARRAYSIZE(k_Ports); i++) {
                if (!UPnPMapPort(&urls, &data, k_Ports[i].proto, portMappingInternalAddress, k_Ports[i].port, enable, false, true)) {
                    success = false;
                }
            }
        }
        else {
            printf("aborted\n");
        }
    }

    FreeUPNPUrls(&urls);
    return success;
}

bool NATPMPMapPort(natpmp_t* natpmp, int proto, int port, bool enable, bool indefinite)
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

    int lifetime;

    if (!enable) {
        lifetime = 0;
    }
    else if (indefinite) {
        lifetime = 604800; // 1 week
    }
    else {
        lifetime = PORT_MAPPING_DURATION_SEC;
    }

    printf("Updating NAT-PMP port mapping for %s %d...", proto == IPPROTO_TCP ? "TCP" : "UDP", port);
    int err = sendnewportmappingrequest(natpmp, natPmpProto, port, enable ? port : 0, lifetime);
    if (err < 0) {
        printf("ERROR %d\n", err);
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
            printf("WAIT FAILED: %d\n", err);
            return false;
        }

        select(0, &fds, nullptr, nullptr, &timeout);

        err = readnatpmpresponseorretry(natpmp, &response);
    } while (err == NATPMP_TRYAGAIN);

    if (err != 0) {
        printf("FAILED %d\n", err);
        return false;
    }
    else if (response.pnu.newportmapping.lifetime == 0 && !enable) {
        printf("DELETED\n");
        return true;
    }
    else if (response.pnu.newportmapping.mappedpublicport != port) {
        printf("CONFLICT\n");

        // It couldn't assign us the external port we requested and gave us an alternate external port.
        // We can't use this alternate mapping, so immediately release it.
        printf("Deleting unwanted NAT-PMP mapping for %s %d...", proto == IPPROTO_TCP ? "TCP" : "UDP", response.pnu.newportmapping.mappedpublicport);
        err = sendnewportmappingrequest(natpmp, natPmpProto, response.pnu.newportmapping.privateport, 0, 0);
        if (err < 0) {
            printf("ERROR %d\n", err);
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
                    printf("WAIT FAILED: %d\n", err);
                    return false;
                }

                select(0, &fds, nullptr, nullptr, &timeout);

                err = readnatpmpresponseorretry(natpmp, &response);
            } while (err == NATPMP_TRYAGAIN);

            if (err == 0) {
                printf("OK\n");
                return false;
            }
            else {
                printf("FAILED %d\n", err);
                return false;
            }
        }
    }
    else {
        printf("OK (%d seconds remaining)\n", response.pnu.newportmapping.lifetime);
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
        printf("RegQueryValueExA() failed: %d\n", error);
        return false;
    }

    return enabled != 0;
}

bool IsAlternateHostSoftwareRunning()
{
    int err;
    PMIB_TCPTABLE tcp_table = nullptr;
    ULONG table_size = 0;

    do {
        // Query all open TCPv4 sockets
        err = GetTcpTable(tcp_table, &table_size, false);
        if (err == ERROR_INSUFFICIENT_BUFFER) {
            free(tcp_table);
            tcp_table = (PMIB_TCPTABLE)malloc(table_size);
        }
    } while (err == ERROR_INSUFFICIENT_BUFFER);

    if (!tcp_table || err != NO_ERROR) {
        printf("GetTcpTable() failed: %d\n", err);
        free(tcp_table);
        return false;
    }

    bool result = false;
    for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
        auto& entry = tcp_table->table[i];

        // Look for TCP 47989 port in the listening state
        if (entry.dwLocalPort == _byteswap_ushort(47989) && entry.dwState == MIB_TCP_STATE_LISTEN) {
            result = true;
            break;
        }
    }

    free(tcp_table);
    return result;
}

void UpdatePortMappingsForTarget(bool enable, char* targetAddressIP4, char* internalAddressIP4, char* upstreamAddressIP4)
{
    natpmp_t natpmp;
    bool tryNatPmp = true;
    bool tryPcp = true;
    char upstreamAddrNatPmp[128] = {};
    char upstreamAddrUPnP[128] = {};

    printf("Starting port mapping update on %s to %s...\n",
        targetAddressIP4 ? targetAddressIP4 : "default gateway",
        internalAddressIP4 ? internalAddressIP4 : "local machine");

    int natPmpErr = initnatpmp(&natpmp, targetAddressIP4 ? 1 : 0, targetAddressIP4 ? inet_addr(targetAddressIP4) : 0);
    if (natPmpErr != 0) {
        printf("initnatpmp() failed: %d\n", natPmpErr);
    }
    else {
        natPmpErr = sendpublicaddressrequest(&natpmp);
        if (natPmpErr < 0) {
            printf("sendpublicaddressrequest() failed: %d\n", natPmpErr);
            closenatpmp(&natpmp);
        }
    }

    fflush(stdout);

    {
        int upnpErr;
        struct UPNPDev* ipv4Devs;
        
        if (targetAddressIP4 == nullptr) {
            // If we have no target, use discovery to find the first hop
            ipv4Devs = upnpDiscoverAll(UPNP_DISCOVERY_DELAY_MS, nullptr, nullptr, UPNP_LOCAL_PORT_ANY, 0, 2, &upnpErr);
            printf("UPnP IPv4 IGD discovery completed with error code: %d\n", upnpErr);
        }
        else {
            // We have a specified target, so do discovery against that directly (may be outside our subnet in case of double-NAT)
            struct in_addr addr;
            addr.S_un.S_addr = inet_addr(targetAddressIP4);
            ipv4Devs = getUPnPDevicesByAddress(addr);
        }

        // Abort if this is an add/update request and we're stopping
        if (enable && WaitForSingleObject(s_StopEvent, 0) == WAIT_OBJECT_0) {
            printf("Aborting port mapping update due to stop request\n");
            goto Exit;
        }

        // Use the delay of discovery to also allow the NAT-PMP endpoint time to respond
        if (natPmpErr >= 0) {
            natpmpresp_t response;
            natPmpErr = readnatpmpresponseorretry(&natpmp, &response);
            if (natPmpErr == 0) {
                inet_ntop(AF_INET, &response.pnu.publicaddress.addr, upstreamAddrNatPmp, sizeof(upstreamAddrNatPmp));
                printf("NAT-PMP upstream address is: %s\n", upstreamAddrNatPmp);
            }
            else {
                printf("NAT-PMP public address request failed: %d\n", natPmpErr);
                closenatpmp(&natpmp);
            }
        }

        // Don't try NAT-PMP if UPnP succeeds
        if (UPnPHandleDeviceList(ipv4Devs, enable, internalAddressIP4, upstreamAddrUPnP)) {
            printf("UPnP IPv4 port mapping successful\n");
            if (enable) {
                // We still want to try NAT-PMP if we're removing
                // rules to ensure any NAT-PMP rules get cleaned up
                tryNatPmp = false;
                tryPcp = false;
            }
        }

        freeUPNPDevlist(ipv4Devs);
    }

    fflush(stdout);

    if (natPmpErr == 0) {
        // NAT-PMP has no description field or other token that we can use to determine
        // if we created the rules we'd be deleting. Since we don't have that, we can't
        // safely remove mappings that could be shared by another machine behind a double NAT.
        if (!enable && targetAddressIP4 != nullptr) {
            printf("Not removing upstream NAT-PMP mappings on non-default gateway device\n");
            tryNatPmp = false;
        }

        // Don't try with NAT-PMP if the UPnP attempt for the same gateway failed due to being
        // disconnected or some other error. This will avoid overwriting UPnP rules on a disconnected IGD
        // with duplicate NAT-PMP rules. We want to allow deletion of NAT-PMP rules in any case though.
        if (enable && !strcmp(upstreamAddrNatPmp, upstreamAddrUPnP)) {
            printf("Not attempting to use NAT-PMP/PCP to talk to the same UPnP gateway\n");
            tryNatPmp = false;

            // We have both UPnP and NAT-PMP on the same upstream gateway, so let's
            // assume PCP is on the same box too.
            tryPcp = false;
        }

        if (tryNatPmp) {
            bool success = true;
            for (int i = 0; i < ARRAYSIZE(k_Ports); i++) {
                if (!NATPMPMapPort(&natpmp, k_Ports[i].proto, k_Ports[i].port, enable, false)) {
                    success = false;
                }
            }

            // We can only map ports for the non-default gateway case because
            // it will use our LAN address as the internal client address, which
            // doesn't work (needs to be broadcast) for the last hop.
            if (targetAddressIP4 != nullptr) {
                // Best effort, don't care if we fail for WOL
                for (int i = 0; i < ARRAYSIZE(k_WolPorts); i++) {
                    // Indefinite mapping since we may not be awake to refresh it
                    NATPMPMapPort(&natpmp, IPPROTO_UDP, k_WolPorts[i], enable, true);
                }
            }

            if (success) {
                printf("NAT-PMP IPv4 port mapping successful\n");

                // Always try all possibilities when disabling to ensure
                // we completely clean up
                if (enable) {
                    tryPcp = false;
                }
            }
        }

        closenatpmp(&natpmp);
    }

    // Try PCP for IPv4 if UPnP and NAT-PMP have both failed. This may be the case for CGN that only supports PCP.
    if (tryPcp) {
        SOCKADDR_IN targetAddr = {};
        SOCKADDR_IN internalAddr = {};

        targetAddr.sin_family = AF_INET;
        internalAddr.sin_family = AF_INET;

        if (targetAddressIP4 != nullptr && internalAddressIP4 != nullptr) {
            targetAddr.sin_addr.S_un.S_addr = inet_addr(targetAddressIP4);
            internalAddr.sin_addr.S_un.S_addr = inet_addr(internalAddressIP4);
        }
        else {
            MIB_IPFORWARDROW route;
            DWORD error = GetBestRoute(0, 0, &route);
            if (error == NO_ERROR) {
                targetAddr.sin_addr.S_un.S_addr = route.dwForwardNextHop;
            }
            else {
                printf("GetBestRoute() failed: %d\n", error);
                goto Exit;
            }
        }

        bool success = true;
        for (int i = 0; i < ARRAYSIZE(k_Ports); i++) {
            if (!PCPMapPort((PSOCKADDR_STORAGE)&internalAddr, sizeof(internalAddr),
                (PSOCKADDR_STORAGE)&targetAddr, sizeof(targetAddr),
                k_Ports[i].proto, k_Ports[i].port, enable, false)) {
                success = false;
            }
        }

        // We can only map ports for the non-default gateway case because
        // it will use our internal address as the internal client address, which
        // doesn't work (needs to be broadcast) for the last hop.
        if (internalAddressIP4 != nullptr) {
            // Best effort, don't care if we fail for WOL
            for (int i = 0; i < ARRAYSIZE(k_WolPorts); i++) {
                // Indefinite mapping since we may not be awake to refresh it
                PCPMapPort((PSOCKADDR_STORAGE)&internalAddr, sizeof(internalAddr),
                    (PSOCKADDR_STORAGE)&targetAddr, sizeof(targetAddr),
                    IPPROTO_UDP, k_WolPorts[i], enable, true);
            }
        }

        if (success) {
            printf("PCP IPv4 port mapping successful\n");
        }
    }

Exit:
    // Write this at the end to avoid clobbering an input parameter
    if (upstreamAddrNatPmp[0] != 0 && inet_addr(upstreamAddrNatPmp) != 0) {
        printf("Using NAT-PMP upstream IPv4 address: %s\n", upstreamAddrNatPmp);
        strcpy(upstreamAddressIP4, upstreamAddrNatPmp);
    }
    else if (upstreamAddrUPnP[0] != 0 && inet_addr(upstreamAddrUPnP) != 0) {
        printf("Using UPnP upstream IPv4 address: %s\n", upstreamAddrUPnP);
        strcpy(upstreamAddressIP4, upstreamAddrUPnP);
    }
    else {
        printf("No valid upstream IPv4 address found!\n");
        upstreamAddressIP4[0] = 0;
    }
}

bool IsLikelyNAT(unsigned long netByteOrderAddr)
{
    DWORD addr = htonl(netByteOrderAddr);

    // 10.0.0.0/8
    if ((addr & 0xFF000000) == 0x0A000000) {
        return true;
    }
    // 172.16.0.0/12
    else if ((addr & 0xFFF00000) == 0xAC100000) {
        return true;
    }
    // 192.168.0.0/16
    else if ((addr & 0xFFFF0000) == 0xC0A80000) {
        return true;
    }
    // 100.64.0.0/10 - RFC6598 official CGN address
    else if ((addr & 0xFFC00000) == 0x64400000) {
        return true;
    }

    return false;
}

void UpdatePortMappings(bool enable)
{
    IN_ADDR hops[4];
    int hopCount = ARRAYSIZE(hops);
    char upstreamAddrStr[128];
    unsigned long upstreamAddr;

    printf("Finding upstream IPv4 hops via traceroute...\n");
    if (!getHopsIP4(hops, &hopCount)) {
        hopCount = 0;
    }
    else {
        printf("Found %d hops\n", hopCount);
    }

    // getHopsIP4() already skips the default gateway, so 0
    // is actually the first hop after the default gateway
    int nextHopIndex = 0;

    // Start by probing for the default gateway
    UpdatePortMappingsForTarget(enable, nullptr, nullptr, upstreamAddrStr);
    while (upstreamAddrStr[0] != 0 && (upstreamAddr = inet_addr(upstreamAddrStr)) != 0) {
        // We got an upstream address. Let's check if this is a NAT
        if (IsLikelyNAT(upstreamAddr)) {
            printf("Upstream address %s is likely a NAT\n", upstreamAddrStr);

            if (nextHopIndex >= hopCount) {
                printf("Traceroute didn't reach this hop! Aborting!\n");
                break;
            }

            char targetAddress[128];
            inet_ntop(AF_INET, &hops[nextHopIndex], targetAddress, sizeof(targetAddress));

            // It's a NAT, so let's direct our UPnP/NAT-PMP messages to it.
            // The internal IP address for the new mapping will be the upstream address of the last one.
            // The target IP address to which to send the UPnP/NAT-PMP is the next hop of the traceroute.
            UpdatePortMappingsForTarget(enable, targetAddress, upstreamAddrStr, upstreamAddrStr);
        }
        else {
            // If we reach a proper public IP address, we're done
            printf("Reached the Internet at hop %d\n", nextHopIndex);
            break;
        }

        // Next hop
        nextHopIndex++;
    }

    fflush(stdout);
}

void NETIOAPI_API_ IpInterfaceChangeNotificationCallback(PVOID context, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE)
{
    SetEvent((HANDLE)context);
}

void ResetLogFile(bool standaloneExe)
{
    char timeString[MAX_PATH + 1] = {};
    SYSTEMTIME time;

    if (!standaloneExe) {
        char oldLogFilePath[MAX_PATH + 1];
        char currentLogFilePath[MAX_PATH + 1];

        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\miss-old.log", oldLogFilePath, sizeof(oldLogFilePath));
        ExpandEnvironmentStringsA("%ProgramData%\\MISS\\miss-current.log", currentLogFilePath, sizeof(currentLogFilePath));

        // Close the existing stdout handle. This is important because otherwise
        // it may still be open as stdout when we try to MoveFileEx below.
        fclose(stdout);

        // Rotate the current to the old log file
        MoveFileExA(currentLogFilePath, oldLogFilePath, MOVEFILE_REPLACE_EXISTING);

        // Redirect stdout to this new file
        if (freopen(currentLogFilePath, "w", stdout) == NULL) {
            // If we couldn't create a log file, just redirect stdout to NUL.
            // We have to open _something_ or printf() will crash.
            freopen("NUL", "w", stdout);
        }
    }

    // Print a log header
    printf("Moonlight Internet Streaming Service v" VER_VERSION_STR "\n");

    // Print the current time
    GetSystemTime(&time);
    GetTimeFormatA(LOCALE_SYSTEM_DEFAULT, 0, &time, "hh':'mm':'ss tt", timeString, ARRAYSIZE(timeString));
    printf("The current UTC time is: %s\n", timeString);
}

DWORD WINAPI GameStreamStateChangeThread(PVOID Context)
{
    HKEY key;
    DWORD err;

    do {
        // We're watching this key that way we can still detect GameStream turning on
        // if GFE wasn't even installed when our service started
        do {
            err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\NVIDIA Corporation", 0, KEY_READ | KEY_WOW64_64KEY, &key);
            if (err != ERROR_SUCCESS) {
                // Wait 10 seconds and try again
                Sleep(10000);
            }
        } while (err != ERROR_SUCCESS);

        // Notify the main thread when the GameStream state changes
        bool lastGameStreamState = IsGameStreamEnabled();
        while ((err = RegNotifyChangeKeyValue(key, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, nullptr, false)) == ERROR_SUCCESS) {
            bool currentGameStreamState = IsGameStreamEnabled();
            if (lastGameStreamState != currentGameStreamState) {
                SetEvent((HANDLE)Context);
            }
            lastGameStreamState = currentGameStreamState;
        }

        // If the key is deleted (by DDU or similar), we will hit this code path and poll until it comes back.
        RegCloseKey(key);
    } while (err == ERROR_KEY_DELETED);

    return err;
}

int Initialize()
{
    // Create the stop event
    s_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (s_StopEvent == NULL) {
        return GetLastError();
    }

    InitializeCriticalSection(&s_PortMappingUpdateLock);
    return 0;
}

int Run(bool standaloneExe)
{
    HANDLE ifaceChangeEvent = CreateEvent(nullptr, true, false, nullptr);
    HANDLE gsChangeEvent = CreateEvent(nullptr, true, false, nullptr);
    HANDLE events[3] = { ifaceChangeEvent, gsChangeEvent, s_StopEvent };

    ResetLogFile(standaloneExe);

    // Bump the process priority class to above normal. The UDP relay threads will
    // further raise their own thread priorities to avoid preemption by other activity.
    SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);

    // Create the UDP alternate port relays
    for (int i = 0; i < ARRAYSIZE(k_Ports); i++) {
        if (k_Ports[i].proto == IPPROTO_UDP) {
            StartUdpRelay(k_Ports[i].port);
        }
    }

    // Create the thread to watch for GameStream state changes
    CreateThread(nullptr, 0, GameStreamStateChangeThread, gsChangeEvent, 0, nullptr);

    // Watch for IP address and interface changes
    HANDLE ifaceChangeHandle;
    NotifyIpInterfaceChange(AF_UNSPEC, IpInterfaceChangeNotificationCallback, ifaceChangeEvent, false, &ifaceChangeHandle);

    for (;;) {
        ResetEvent(gsChangeEvent);
        ResetEvent(ifaceChangeEvent);

        bool gameStreamEnabled = IsGameStreamEnabled();

        if (gameStreamEnabled) {
            printf("GFE GameStream is ON!\n");
        }
        else {
            printf("GFE GameStream is OFF!\n");

            if (IsAlternateHostSoftwareRunning()) {
                printf("Sunshine is RUNNING!\n");
                gameStreamEnabled = true;
            }
            else {
                printf("Sunshine is NOT RUNNING!\n");
            }
        }

        // Acquire the mapping lock and update port mappings
        if (TryEnterCriticalSection(&s_PortMappingUpdateLock)) {
            // If the stop event is set, bail out now
            if (WaitForSingleObject(s_StopEvent, 0) == WAIT_OBJECT_0) {
                LeaveCriticalSection(&s_PortMappingUpdateLock);
                return 0;
            }

            UpdatePortMappings(gameStreamEnabled);
            LeaveCriticalSection(&s_PortMappingUpdateLock);
        }

        // Refresh when half the duration is expired or if an IP interface
        // change event occurs.
        printf("Going to sleep...\n");
        fflush(stdout);

        ULONGLONG beforeSleepTime = GetTickCount64();
        DWORD ret = WaitForMultipleObjects(ARRAYSIZE(events), events, false, POLLING_DELAY_SEC * 1000);
        if (ret == WAIT_OBJECT_0) {
            ResetLogFile(standaloneExe);

            printf("Woke up for interface change notification after %lld seconds\n",
                (GetTickCount64() - beforeSleepTime) / 1000);

            // Wait a little bit for the interface to settle down (DHCP, RA, etc)
            Sleep(10000);
        }
        else if (ret == WAIT_OBJECT_0 + 1) {
            ResetLogFile(standaloneExe);

            printf("Woke up for GameStream state change notification after %lld seconds\n",
                (GetTickCount64() - beforeSleepTime) / 1000);
        }
        else if (ret == WAIT_OBJECT_0 + 2) {
            printf("Woke up for stop notification\n");
            return 0;
        }
        else {
            ResetLogFile(standaloneExe);

            printf("Woke up for periodic refresh\n");
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
        // Stop future port mapping updates
        SetEvent(s_StopEvent);

        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        ServiceStatus.dwControlsAccepted = 0;
        ServiceStatus.dwWaitHint = 120 * 1000; // 2 minutes
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

        // Remove existing port mappings
        EnterCriticalSection(&s_PortMappingUpdateLock);
        printf("Removing UPnP/NAT-PMP/PCP rules after service stop request\n");
        UpdatePortMappings(false);
        LeaveCriticalSection(&s_PortMappingUpdateLock);

        printf("The service is stopping now\n");
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
        fprintf(stderr, "RegisterServiceCtrlHandlerEx() failed: %d\n", GetLastError());
        return;
    }

    err = Initialize();
    if (err != 0) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        ServiceStatus.dwWin32ExitCode = err;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
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
    err = Run(false);
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
        Initialize();
        return Run(true);
    }

    return StartServiceCtrlDispatcher(ServiceTable);
}