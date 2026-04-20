#include <windows.h>
#include "common.h"

void* _memcpy(void *dst, const void *src, size_t n){
    volatile unsigned char *d = dst;
    const unsigned char *s = src;

    if ((size_t)dst - (size_t)src >= n){
        while (n--)
            *d++ = *s++;
    }
    else{
        d += n - 1;
        s += n - 1;
        while (n--)
            *d-- = *s--;
    }
    return dst;
}

int _strcmp(const char *str1, const char *str2){
    while (*str1 && *str1 == *str2){
        str1++;
        str2++;
    }
    if ((unsigned char)*str1 > (unsigned char)*str2)
        return 1;
    if ((unsigned char)*str1 < (unsigned char)*str2)
        return -1;
    return 0;
}

int _strncmp(const char *str1, const char *str2, size_t n) {
    while (n && *str1 && *str1 == *str2) {
        str1++;
        str2++;
        n--;
    }
    if (!n)
        return 0;
    if ((unsigned char)*str1 > (unsigned char)*str2)
        return 1;
    if ((unsigned char)*str1 < (unsigned char)*str2)
        return -1;
    return 0;
}

int _memcmp(const void *ptr1, const void *ptr2, size_t n){
    const unsigned char *p1, *p2;

    for (p1 = ptr1, p2 = ptr2; n; n--, p1++, p2++){
        if (*p1 < *p2)
            return -1;
        if (*p1 > *p2)
            return 1;
    }
    return 0;
}

unsigned int _wcslen(LPCWSTR str){
    const WCHAR *s = str;
    while (*s)
        s++;
    return s - str;
}

void* memcpy(void *dst, const void *src, size_t n){
    volatile unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--)
        *d++ = *s++;
    return dst;
}

void* memset(void *dst, int c, size_t n){
    volatile unsigned char *d = dst;
    while (n--)
        *d++ = (unsigned char)c;
    return dst;
}

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* Base64Encode(PBYTE data, ULONG size) {
    ULONG outLen = ((size + 2) / 3) * 4 + 1;
    char* out = MemAlloc(outLen);
    if (!out) return NULL;

    ULONG i = 0, j = 0;
    while (i < size) {
        ULONG rem  = size - i;
        BYTE  b0   = data[i++];
        BYTE  b1   = rem > 1 ? data[i++] : 0;
        BYTE  b2   = rem > 2 ? data[i++] : 0;
        out[j++] = b64chars[b0 >> 2];
        out[j++] = b64chars[((b0 & 3) << 4) | (b1 >> 4)];
        out[j++] = rem > 1 ? b64chars[((b1 & 0xF) << 2) | (b2 >> 6)] : '=';
        out[j++] = rem > 2 ? b64chars[b2 & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

SYSTEMTIME ConvertToSystemtime(LARGE_INTEGER li) {
    FILETIME ft;
    SYSTEMTIME st = { 0 };
    ft.dwHighDateTime = li.HighPart;
    ft.dwLowDateTime = li.LowPart;
    KERNEL32$FileTimeToSystemTime(&ft, &st);
    return st;
}
