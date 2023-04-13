#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock2.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")

#define MAX_BUF_SIZE 2048
#define SERVER_PORT 8080
#define SERVER_ADDR "127.0.0.1"
#define CLIENT_CERT "C:\\Users\\64515\\Desktop\\毕业设计\\客户端\\client\\x64\\Release\\client.crt"
#define CLIENT_KEY "C:\\Users\\64515\\Desktop\\毕业设计\\客户端\\client\\x64\\Release\\client.key"
#define CA_CERT "C:\\Users\\64515\\Desktop\\毕业设计\\客户端\\client\\x64\\Release\\ca.crt"

int CheckCert(SSL* ssl);
int main(int argc, char *argv[])
{
    WSADATA wsaData;
    SSL_CTX* ctx;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stdout);
        return -1;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);//启动双项认证
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) <= 0)//加载根证书
    {
        printf("SSL_CTX_load_verify_locations failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0)//加载用户证书
    {
        printf("SSL_CTX_use_certificate_file failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0)//加载证书私钥
    {
        printf("SSL_CTX_use_PrivateKey_file failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (!SSL_CTX_check_private_key(ctx))//检查证书私钥一致性
    {
        printf("Private key does not match the certificate public key\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET)
    {
        printf("socket failed\n");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    //InetPton(AF_INET, SERVER_ADDR, &server_addr);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        printf("connect failed\n");
        return -1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) == -1)
    {
        printf("SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        if (CheckCert(ssl) != 1) {
            printf("程序已结束\n");
            return -1;
        }
    }

    char buf[MAX_BUF_SIZE];
    for(;;)
    {
        memset(buf, 0, MAX_BUF_SIZE);
        printf("Client enter message to send (q to quit):\n");
        fgets(buf, MAX_BUF_SIZE, stdin);
        buf[strlen(buf) - 1] = 0;
        if (strcmp(buf, "q") == 0) {
            break;
        }

        SSL_write(ssl, buf, (strlen(buf)+1));

        int ret = SSL_read(ssl, buf, MAX_BUF_SIZE);
        buf[ret] = '\0';
        printf("Received message: %s\n", buf);

    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    closesocket(sockfd);
    WSACleanup();

    return 0;
}

int CheckCert(SSL* ssl) {
    X509* cert;
    char* line;
    cert = SSL_get_peer_certificate(ssl);

    if (cert != NULL) {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else {
        printf("无证书信息！\n");
        return -1;
    }

    
    if (SSL_get_verify_result(ssl) == X509_V_OK) {
        printf("证书验证通过\n");
        return 1;
    }
    else {
        printf("证书验证失败\n");
        return -1;
    }
}