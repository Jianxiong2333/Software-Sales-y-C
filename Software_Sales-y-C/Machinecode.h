#pragma once
#include <locale.h>
#include <tchar.h>
#include <Winsock2.h>//��ͷһ��������Windows.h
#include <windows.h>
#include <stdlib.h>
#include <Iptypes.h>
#include <iphlpapi.h>
#include <string.h>
#include <openssl/md5.h>//��������Ŀ������OpenSSL
#include <stdio.h>

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "Iphlpapi.lib")

//Disk
char * flipAndCodeBytes(const char * str,
    int pos,
    int flip,
    char * buf)
{
    int i;
    int j = 0;
    int k = 0;

    buf[0] = '\0';
    if (pos <= 0)
        return buf;

    if (!j)
    {
        char p = 0;

        // First try to gather all characters representing hex digits only.
        j = 1;
        k = 0;
        buf[k] = 0;
        for (i = pos; j && str[i] != '\0'; ++i)
        {
            char c = tolower(str[i]);

            if (isspace(c))
                c = '0';

            ++p;
            buf[k] <<= 4;

            if (c >= '0' && c <= '9')
                buf[k] |= (unsigned char)(c - '0');
            else if (c >= 'a' && c <= 'f')
                buf[k] |= (unsigned char)(c - 'a' + 10);
            else
            {
                j = 0;
                break;
            }

            if (p == 2)
            {
                if (buf[k] != '\0' && !isprint(buf[k]))
                {
                    j = 0;
                    break;
                }
                ++k;
                p = 0;
                buf[k] = 0;
            }

        }
    }

    if (!j)
    {
        // There are non-digit characters, gather them as is.
        j = 1;
        k = 0;
        for (i = pos; j && str[i] != '\0'; ++i)
        {
            char c = str[i];

            if (!isprint(c))
            {
                j = 0;
                break;
            }

            buf[k++] = c;
        }
    }

    if (!j)
    {
        // The characters are not there or are not printable.
        k = 0;
    }

    buf[k] = '\0';

    if (flip)
        // Flip adjacent characters
        for (j = 0; j < k; j += 2)
        {
            char t = buf[j];
            buf[j] = buf[j + 1];
            buf[j + 1] = t;
        }

    // Trim any beginning and end space
    i = j = -1;
    for (k = 0; buf[k] != '\0'; ++k)
    {
        if (!isspace(buf[k]))
        {
            if (i < 0)
                i = k;
            j = k;
        }
    }

    if ((i >= 0) && (j >= 0))
    {
        for (k = i; (k <= j) && (buf[k] != '\0'); ++k)
            buf[k - i] = buf[k];
        buf[k - i] = '\0';
    }

    return buf;
}

/************************************************************************
GetHDSerial�����ڻ�ȡָ����ŵ�Ӳ�����кţ������κ�Ȩ������
������
PCHAR pszIDBuff��������ַ��������������ڽ���Ӳ�����к�
int nBuffLen��������ַ�����������С����Ӳ�����кŴ��ڸ�ֵʱ��ֻ����nBuffLen����
int nDriveID��Ҫ��ȡ����������ţ���0��ʼ����15Ϊֹ
����ֵ��
�ɹ���ȡ����Ӳ�����кų��ȣ�Ϊ0��ʾ��ȡʧ��
���ߣ�
famous214��blog.csdn.net/LPWSTR��
Դ��ο���diskid32��https://www.winsim.com/diskid32/diskid32.html��
�汾��ʷ��
20171226 ��һ�棬��diskid32Դ������ȡ
20171226 �ڶ��棬����Unicode���뷽ʽ
20171230 �ع��󷢲�������
************************************************************************/
ULONG GetHDSerial(PCHAR pszIDBuff, int nBuffLen, int nDriveID)
{
    HANDLE hPhysicalDrive = INVALID_HANDLE_VALUE;
    ULONG ulSerialLen = 0;
    __try
    {
        //  Try to get a handle to PhysicalDrive IOCTL, report failure
        //  and exit if can't.
        TCHAR szDriveName[32];
        wsprintf(szDriveName, TEXT("\\\\.\\PhysicalDrive%d"), nDriveID);

        //  Windows NT, Windows 2000, Windows XP - admin rights not required
        hPhysicalDrive = CreateFile(szDriveName, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
            OPEN_EXISTING, 0, NULL);
        if (hPhysicalDrive == INVALID_HANDLE_VALUE)
        {
            __leave;
        }
        STORAGE_PROPERTY_QUERY query;
        DWORD cbBytesReturned = 0;
        static char local_buffer[10000];

        memset((void *)&query, 0, sizeof(query));
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        memset(local_buffer, 0, sizeof(local_buffer));

        if (DeviceIoControl(hPhysicalDrive, IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            sizeof(query),
            &local_buffer[0],
            sizeof(local_buffer),
            &cbBytesReturned, NULL))
        {
            STORAGE_DEVICE_DESCRIPTOR * descrip = (STORAGE_DEVICE_DESCRIPTOR *)& local_buffer;
            char serialNumber[1000];

            flipAndCodeBytes(local_buffer,
                descrip->SerialNumberOffset,
                1, serialNumber);

            if (isalnum(serialNumber[0]))
            {
                ULONG ulSerialLenTemp = strnlen(serialNumber, nBuffLen - 1);
                memcpy(pszIDBuff, serialNumber, ulSerialLenTemp);
                pszIDBuff[ulSerialLenTemp] = NULL;
                ulSerialLen = ulSerialLenTemp;
                __leave;
            }

        }
    }
    __finally
    {
        if (hPhysicalDrive != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hPhysicalDrive);
        }
        return ulSerialLen;
    }
}

char* GetAllHDSerial()
{
    const int MAX_IDE_DRIVES = 16;
    static char szBuff[0x100];
    int nDriveNum = 0;//ȡ�� 0 ��Ӳ�����к�
    ULONG ulLen = GetHDSerial(szBuff, sizeof(szBuff), nDriveNum);
    //    printf("��%d��Ӳ�̵����к�Ϊ��%hs\n", nDriveNum + 1, szBuff);
    return szBuff;//�������к�
}

//Mac
static char* PrintMACaddress(unsigned char MACData[])
{
    char Code[50];
    sprintf_s(Code, "%d%d%d%d%d%d", MACData[0], MACData[1], MACData[2], MACData[3], MACData[4], MACData[5]); //��������ַת��ʮ���ƣ��ٸ�ʽ��д���ַ���
    return Code;
}

static char* GetMacAddress(void)
{

    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBuflen = sizeof(AdapterInfo);

    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBuflen);

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;

    // do {
    return PrintMACaddress(pAdapterInfo->Address);//���ش˺������صĸ�ʽ��������ַ
                                                  //pAdapterInfo = pAdapterInfo->Next;//ָ����һ��������ע�͵�ʼ�ն�ȡ��̫�������ſ�ע�ͻ��Զ��������п�������
                                                  // } while (pAdapterInfo);

}

char* Get_md5(char* Plaintext)
{
    const char *data = Plaintext;  // ԭʼ����
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

    //printf("%s\n", buf); // data��md5ֵ
    return buf; //����ժҪ
}

char* Machinecode(void)
{
    char Machine_Code[170] = { 0 };//������
                                   //setlocale(LC_ALL, "chs");// ���ü�������
    strcat_s(Machine_Code, sizeof(Machine_Code), Get_md5(GetMacAddress()));  //ƴ��ժҪ����������кţ�MD5Ϊ32λ������/0 33λ
    strcat_s(Machine_Code, sizeof(Machine_Code), Get_md5(GetAllHDSerial())); //ƴ��ժҪ���Ӳ�����кţ�MD5Ϊ32λ������/0 33λ
    return Machine_Code;//����64λ������Ӳ�̵�ժҪƴ��
}
