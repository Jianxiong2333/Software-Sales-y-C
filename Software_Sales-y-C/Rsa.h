#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

// I'm not using BIO for base64 encoding/decoding.  It is difficult to use.
// Using superwills' Nibble And A Half instead 
// https://github.com/superwills/NibbleAndAHalf/blob/master/NibbleAndAHalf/base64.h
#include "Base64.h"

// The PADDING parameter means RSA will pad your data for you
// if it is not exactly the right size
//#define PADDING RSA_PKCS1_OAEP_PADDING
#define PADDING RSA_PKCS1_PADDING
//#define PADDING RSA_NO_PADDING

RSA* loadPUBLICKeyFromString(const char* publicKeyStr)
{
    // A BIO is an I/O abstraction (Byte I/O?)

    // BIO_new_mem_buf: Create a read-only bio buf with data
    // in string passed. -1 means string is null terminated,
    // so BIO_new_mem_buf can find the dataLen itself.
    // Since BIO_new_mem_buf will be READ ONLY, it's fine that publicKeyStr is const.
    BIO* bio = BIO_new_mem_buf((void*)publicKeyStr, -1); // -1: assume string is null terminated

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // NO NL

                                                // Load the RSA key from the BIO
    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsaPubKey)
        printf("ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));//公钥无法加载（错误）

    BIO_free(bio);
    return rsaPubKey;
}

RSA* loadPRIVATEKeyFromString(const char* privateKeyStr)
{
    BIO *bio = BIO_new_mem_buf((void*)privateKeyStr, -1);
    //BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
    RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    if (!rsaPrivKey)
        printf("ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));//私钥无法加载（错误）

    BIO_free(bio);
    return rsaPrivKey;
}

unsigned char* rsaEncrypt(RSA *pubKey, const unsigned char* str, int dataSize, int *resultLen)
{
    int rsaLen = RSA_size(pubKey);
    unsigned char* ed = (unsigned char*)malloc(rsaLen);

    // RSA_public_encrypt() returns the size of the encrypted data
    // (i.e., RSA_size(rsa)). RSA_private_decrypt() 
    // returns the size of the recovered plaintext.
    *resultLen = RSA_public_encrypt(dataSize, (const unsigned char*)str, ed, pubKey, PADDING);
    if (*resultLen == -1)
        printf("ERROR: RSA_public_encrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));//公钥加密错误

    return ed;
}

unsigned char* rsaDecrypt(RSA *privKey, const unsigned char* encryptedData, int *resultLen)
{
    int rsaLen = RSA_size(privKey); // That's how many bytes the decrypted data would be

    unsigned char *decryptedBin = (unsigned char*)malloc(rsaLen);
    *resultLen = RSA_private_decrypt(RSA_size(privKey), encryptedData, decryptedBin, privKey, PADDING);
    if (*resultLen == -1)
        printf("ERROR: RSA_private_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));//私钥解密错误

    return decryptedBin;
}

// You may need to encrypt several blocks of binary data (each has a maximum size
// limited by pubKey).  You shoudn't try to encrypt more than
// RSA_LEN( pubKey ) bytes into some packet.
// returns base64( rsa encrypt( <<binary data>> ) )
// base64OfRsaEncrypted()
// base64StringOfRSAEncrypted
// rsaEncryptThenBase64
char* rsaEncryptThenBase64(RSA *pubKey, unsigned char* binaryData, int binaryDataLen, int *outLen)
{
    int encryptedDataLen;

    // RSA encryption with public key
    unsigned char* encrypted = rsaEncrypt(pubKey, binaryData, binaryDataLen, &encryptedDataLen);

    // To base 64
    int asciiBase64EncLen;
    char* asciiBase64Enc = base64(encrypted, encryptedDataLen, &asciiBase64EncLen);

    // Destroy the encrypted data (we are using the base64 version of it)
    free(encrypted);

    // Return the base64 version of the encrypted data
    return asciiBase64Enc;
}

// rsaDecryptOfUnbase64()
// rsaDecryptBase64String()
// unbase64ThenRSADecrypt()
// rsaDecryptThisBase64()
unsigned char* rsaDecryptThisBase64(RSA *privKey, char* base64String, int *outLen)
{
    int encBinLen;
    unsigned char* encBin = unbase64(base64String, (int)strlen(base64String), &encBinLen);

    // rsaDecrypt assumes length of encBin based on privKey
    unsigned char *decryptedBin = rsaDecrypt(privKey, encBin, outLen);
    free(encBin);

    return decryptedBin;
}

char* Rsa_encrypt(char* Machine_Code, const char *b64_pKey)//加密函数
{
    ERR_load_crypto_strings();
    unsigned char *str = (unsigned char*)Machine_Code;
    int dataSize = strlen(Machine_Code);//计算长度,加 1 为弥补\0
                                        //printf("\n原始数据为:\n%s\n\n", (char*)str);

                                        // LOAD PUBLIC KEY
    RSA *pubKey = loadPUBLICKeyFromString(b64_pKey);

    int asciiB64ELen;
    char* asciiB64E = rsaEncryptThenBase64(pubKey, str, dataSize, &asciiB64ELen);
    RSA_free(pubKey); // free the public key when you are done all your encryption
    char* rxOverHTTP = asciiB64E; // Simulate Internet connection by a pointer reference
                                  //printf("\nbase64 字符串:\n%s\n", rxOverHTTP);
    ERR_free_strings();

    return rxOverHTTP;//返回加密后 base64 数据
}

char* Rsa_decrypt(char* rxOverHTTP, const char *b64priv_key)//解密函数
{
    ERR_load_crypto_strings();
    // LOAD PUBLIC KEY
    // Now decrypt this very string with the private key
    RSA *privKey = loadPRIVATEKeyFromString(b64priv_key);

    // Now we got the data at the server.  Time to decrypt it.
    int rBinLen;
    unsigned char* rBin = rsaDecryptThisBase64(privKey, rxOverHTTP, &rBinLen);
    char decrypt[128];//解密数据
                      //printf("解密的 %d 字节, 恢复的数据为:%.*s\n\n", rBinLen, rBinLen, rBin); // rBin is not necessarily NULL
                      // terminated, so we only print rBinLen chrs 
    sprintf_s(decrypt, "%.*s", rBinLen, rBin);
    RSA_free(privKey);
    /*调试语句
    if (allEq) puts("DATA TRANSFERRED INTACT!"); //数据完整
    else puts("ERROR, recovered binary does not match sent binary");//数据不匹配
    */
    //free(str);
    //free(asciiB64E); // rxOverHTTP  
    free(rBin);
    ERR_free_strings();

    return decrypt;//返回解密 base64 /Rsa 后的数据
}