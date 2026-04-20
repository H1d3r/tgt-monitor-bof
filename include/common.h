#include <windows.h>
#include <ntsecapi.h>

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_MEMORY_NOT_ALLOCATED ((NTSTATUS)0xC00000A0L)
#define NT_SUCCESS(status)          ((NTSTATUS)(status) >= 0)

#define MemAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define MemFree(ptr)   KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (ptr))

// APIs
// SECUR32
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaRegisterLogonProcess(PLSA_STRING, PHANDLE, PLSA_OPERATIONAL_MODE);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaEnumerateLogonSessions(PULONG, PLUID*);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaGetLogonSessionData(PLUID, PSECURITY_LOGON_SESSION_DATA*);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);

// KERNEL32
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int      WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$WaitForSingleObjectEx(HANDLE, DWORD, BOOLEAN);
DECLSPEC_IMPORT VOID     WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);


// Kerberos structs
typedef struct {
    LUID  luid;
    WCHAR spn[256];
    WCHAR clientName[256];
    WCHAR clientRealm[256];
    WCHAR serverRealm[256];
    KERB_TICKET_CACHE_INFO_EX cacheInfo;
} TICKET_ENTRY, *PTICKET_ENTRY;    

typedef struct {
    PTICKET_ENTRY tickets;
    int           count;
} TICKET_CACHE, *PTICKET_CACHE;    

enum TICKET_FLAGS {
	reserved = 2147483648,
	forwardable = 0x40000000,
	forwarded = 0x20000000,
	proxiable = 0x10000000,
	proxy = 0x08000000,
	may_postdate = 0x04000000,
	postdated = 0x02000000,
	invalid = 0x01000000,
	renewable = 0x00800000,
	initial = 0x00400000,
	pre_authent = 0x00200000,
	hw_authent = 0x00100000,
	ok_as_delegate = 0x00040000,
	anonymous = 0x00020000,
	name_canonicalize = 0x00010000,
	cname_in_pa_data = 0x00040000,
	enc_pa_rep = 0x00010000,
	reserved1 = 0x00000001,
	empty = 0x00000000,
};

enum KERB_ETYPE {
	des_cbc_crc = 1,
	des_cbc_md4 = 2,
	des_cbc_md5 = 3,
	des3_cbc_md5 = 5,
	des3_cbc_sha1 = 7,
	dsaWithSHA1_CmsOID = 9,
	md5WithRSAEncryption_CmsOID = 10,
	sha1WithRSAEncryption_CmsOID = 11,
	rc2CBC_EnvOID = 12,
	rsaEncryption_EnvOID = 13,
	rsaES_OAEP_ENV_OID = 14,
	des_ede3_cbc_Env_OID = 15,
	des3_cbc_sha1_kd = 16,
	aes128_cts_hmac_sha1 = 17,
	aes256_cts_hmac_sha1 = 18,
	rc4_hmac = 23,
	rc4_hmac_exp = 24,
	subkey_keymaterial = 65,
	old_exp = -135,
};

// Core functions
NTSTATUS GetLsaHandle(HANDLE* hLsa); 
NTSTATUS ExtractTicket(HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING target, PUCHAR* ticket, PULONG ticketSize); 
NTSTATUS EnumerateTickets(HANDLE hLsa, ULONG authPackage, char* targetUser, PTICKET_CACHE cache); 
VOID PrintTicketInformation(PTICKET_ENTRY entry, PBYTE ticket, ULONG ticketSize);
char* Base64Encode(PBYTE data, ULONG size);
VOID RefreshCache(HANDLE hLsa, ULONG authPackage, PTICKET_CACHE prev, PTICKET_CACHE curr); 

// Utils
void* _memcpy(void *dst, const void *src, size_t n); 
int _strcmp(const char *str1, const char *str2);
int _strncmp(const char *str1, const char *str2, size_t n);
int _memcmp(const void *ptr1, const void *ptr2, size_t n);
unsigned int _wcslen(LPCWSTR str);
void* memcpy(void *dst, const void *src, size_t n);
void* memset(void *dst, int c, size_t n);
SYSTEMTIME ConvertToSystemtime(LARGE_INTEGER li); 