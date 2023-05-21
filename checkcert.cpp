#include "head.h"

int CheckCert(SSL* ssl) {
    X509* cert;
    char* line;
    cert = SSL_get_peer_certificate(ssl);

    if (cert != NULL) {
        printf("服务器数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        X509_free(cert);
    }
    else {
        printf("无证书信息！\n");
        return -1;
    }

    long flag = SSL_get_verify_result(ssl);
    if (flag == X509_V_OK) {
        printf("证书验证通过\n");
        return 1;
    }
    else if (flag == X509_V_ERR_CERT_HAS_EXPIRED)
    {
        printf("证书已过期\n");
        return -1;
    }
    else if (flag == X509_V_ERR_CERT_NOT_YET_VALID)
    {
        printf("证书未生效\n");
        return -1;
    }
    else if (flag == X509_V_ERR_CERT_UNTRUSTED)
    {
        printf("证书不受信任\n");
        return -1;
    }
    else {
        printf("证书验证失败\n");
        return -1;
    }
}