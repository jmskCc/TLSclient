#include "head.h"

#define SERVER_PORT 446
#define SERVER_ADDR "127.0.0.1"

HANDLE hThread[2];
int main(int argc, char *argv[])
{
    WSADATA wsaData;
    SSL_CTX* ctx;
    EVP_PKEY* pkey;
    X509* cert;
    char addr[2028];
    DWORD dwThreadId;

    int* err = (int*)malloc(sizeof(int));
    *err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (*err != 0) {
        printf("WSAStartup failed with error: %d\n", *err);
        return -1;
    }
    free(err);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    CRYPTO_secure_malloc_init(32768, 1);

    ctx = SSL_CTX_new(TLSv1_2_client_method());
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

    printf("请输入P12文件地址\n");
    scanf("%s", addr);
    if (InitialP12(addr, &pkey, &cert) == -1) {
        printf("InitialP12 failed\n");
        return -1;
    }
    name = GetCNFromCert(cert);

    if (SSL_CTX_use_certificate(ctx, cert) <= 0)//加载用户证书
    {
        printf("SSL_CTX_use_certificate failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0)//加载证书私钥
    {
        printf("SSL_CTX_use_PrivateKey failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (!SSL_CTX_check_private_key(ctx))//检查证书私钥一致性
    {
        printf("Private key does not match the certificate public key\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    /*
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
    */
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
        else
        {
            printf("%s欢迎您\n", name);
        }
    }
    
    hThread[0] = CreateThread(
        NULL,		// 默认安全属性
        NULL,		// 默认堆栈大小
        recv_msg,	// 线程入口地址（执行线程的函数）
        (void*)ssl,		// 传给函数的参数
        0,		// 指定线程立即运行
        &dwThreadId);	// 返回线程的ID号
    hThread[1] = CreateThread(
        NULL,		// 默认安全属性
        NULL,		// 默认堆栈大小
        send_msg,	// 线程入口地址（执行线程的函数）
        (void*) ssl,		// 传给函数的参数
        0,		// 指定线程立即运行
        &dwThreadId);	// 返回线程的ID号

    // 等待线程运行结束
    WaitForMultipleObjects(2, hThread, true, INFINITE);
    CloseHandle(hThread[0]);
    CloseHandle(hThread[1]);
    /*
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
    */
    printf(" Thread Over,Enter anything to over.\n");
    getchar();
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    CRYPTO_secure_malloc_done();
    closesocket(sockfd);
    WSACleanup();

    return 0;
}