#include "head.h"

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