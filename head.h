#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")

#define MAX_BUF_SIZE 2048
#define NAME_SIZE 30
extern HANDLE hThread[2];
extern char* name;

int CheckCert(SSL* ssl);
void GetPassword(char* password);
int InitialP12(char* addr, EVP_PKEY** pkey_s, X509** cert_s);
DWORD WINAPI send_msg(LPVOID lpParam);
DWORD WINAPI recv_msg(LPVOID lpParam);
void error_handling(const char* msg);
char* GetCNFromCert(X509* cert);