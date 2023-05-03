#include "head.h"

int InitialP12(char* addr, EVP_PKEY** pkey_s, X509** cert_s) {
    //unsigned char* p12_str;
   // long p12_size;
    PKCS12* p12;
    EVP_PKEY* pkey = NULL;
    X509* cert = NULL;
    FILE* p12_file = fopen(addr, "rb");
    if (!p12_file) {
        printf("打开P12文件失败");
        return -1;
    }
    p12 = d2i_PKCS12_fp(p12_file, NULL);
    if (!p12) {
        printf("处理P12文件失败");
        return -1;
    }
    fclose(p12_file);
    char* passwd = (char*)OPENSSL_secure_malloc(256);

    printf("请输入P12证书密码\n");
    GetPassword(passwd);
    PKCS12_parse(p12, passwd, &pkey, &cert, NULL);
    OPENSSL_secure_clear_free(passwd, 256);
    *cert_s = cert;
    *pkey_s = pkey;
    /**pkey_s = (EVP_PKEY*)OPENSSL_secure_malloc(EVP_PKEY_size(pkey));
    memcpy(*pkey_s, pkey, EVP_PKEY_size(pkey));
    EVP_PKEY_free(pkey);
    *cert_s = cert;
    *cert_s = (X509*)OPENSSL_secure_malloc(sizeof(*cert));
    memcpy(*cert_s, cert, sizeof(*cert));
    X509_free(cert);*/
    PKCS12_free(p12);
    return 1;
}