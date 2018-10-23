#pragma once
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
using namespace std;

char* Getmd5(char *data_input)
{
    const char *data = data_input;   // ԭʼ����
    unsigned char md[16] = { 0 };

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, strlen(data));
    MD5_Final(md, &ctx);

    int i = 0;
    char buf[33] = { 0 };
    char tmp[3] = { 0 };
    for (i = 0; i < 16; i++)
    {
        sprintf_s(tmp, "%02X", md[i]);
        strcat_s(buf, tmp);
    }
    //strncpy(buf_16, buf + 8, 16);  //ת16λmd5
    //printf("%s", buf);             //ata��md5ֵ
    return buf;                     //����32λmd5
}
char* Getmd5_16(char *data_input)
{
    const char *data = data_input;   // ԭʼ����
    unsigned char md[16] = { 0 };

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, strlen(data));
    MD5_Final(md, &ctx);

    int i = 0;
    char buf[33] = { 0 };
    char buf_16[37] = { 0 };
    char tmp[3] = { 0 };
    for (i = 0; i < 16; i++)
    {
        sprintf_s(tmp, "%02X", md[i]);
        strcat_s(buf, tmp);
    }
    strncpy(buf_16, buf + 8, 16);  //ת16λmd5
                                   //printf("%s", buf);             //ata��md5ֵ
    return buf_16;                     //����16λmd5
}
