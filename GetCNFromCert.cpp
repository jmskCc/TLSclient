#include "head.h"

char* GetCNFromCert(X509* cert) {
    if (!cert) {
        return NULL;
    }

    // 获取主题名称
    X509_NAME* subject_name = X509_get_subject_name(cert);
    if (!subject_name) {
        return NULL;
    }

    // 查找CN条目
    int idx = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
    if (idx == -1) {
        return NULL;
    }

    // 获取CN条目
    X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(subject_name, idx);
    if (!cn_entry) {
        return NULL;
    }

    // 获取ASN1字符串
    ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
    if (!cn_asn1) {
        return NULL;
    }

    // 将ASN1字符串转换为C字符串
    char* cn_str = (char*)ASN1_STRING_data(cn_asn1);

    return cn_str;
}