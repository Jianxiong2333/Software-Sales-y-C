#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#define BUFSIZ 1024 //������������ĵ���ô��
#include <windows.h>

//�׽���
int Getapi(char *url)
{
    /***********����URL������������������Դ��**********/
    char host[BUFSIZ];
    char resource[BUFSIZ];
    char myurl[BUFSIZ];
    char *pHost = 0;
    if (strlen(url) > 2000)
    {
        return 0;
    }

    //��������������Դ��
    strcpy(myurl, url);

    for (pHost = myurl; *pHost != '/' && *pHost != '\0'; ++pHost);

    if ((int)(pHost - myurl) == strlen(myurl))
    {
        strcpy(resource, "/");
    }
    else
    {
        strcpy(resource, pHost);
    }

    *pHost = '\0';
    strcpy(host, myurl);
    //printf("%s\n%s\n", host, resource);


    /*****************����socket************/
    //��ʼ���׽���
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //�����׽���
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        //printf("Failed socket().\n");
        printf("�����׽��ֳ���.\n");
        WSACleanup();
        return 0;
    }

    //����socket����
    struct sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(80);

    //��ȡ�������͵�ַ��Ϣ
    struct hostent *hp = gethostbyname(host);
    if (hp == NULL)
    {
        //printf("Can not find host address.\n");
        //�Ҳ���������ַ
        return 0;
    }
    sockAddr.sin_addr.s_addr = *((unsigned long *)hp->h_addr);

    //���ӵ�������
    if (connect(sock, (SOCKADDR *)&sockAddr, sizeof(sockAddr)) == -1)
    {
        //printf("Failed connect().\n");
        printf("���� connect().���ӷ�����ʧ��\n");
        WSACleanup();
        return 0;
    }


    /****************�������ͨ�ţ��շ�����***************/
    //׼����������
    char request[BUFSIZ] = "";
    //request = "GET " + resource + " HTTP/1.1\r\nHost:" + host + "\r\nConnection:Close\r\n\r\n";
    strcat(request, "GET ");
    strcat(request, resource);
    strcat(request, " HTTP/1.1\r\nHost:");
    strcat(request, host);
    strcat(request, "\r\nConnection:Close\r\n\r\n");

    //��������
    if (SOCKET_ERROR == send(sock, request, sizeof(request), 0))
    {
        printf("Send error.\n");
        closesocket(sock);
        return 0;
    }

    //��������
    static char pageBuf[BUFSIZ];
    //printf("Read: ");
    int ret = 1;
    int ret_i = 1;
    char str[1024];
    while (ret > 0)
    {
        ret = recv(sock, pageBuf, BUFSIZ, 0);
        //printf("%s", pageBuf);
        if (ret_i)
        {
            strcpy(str, pageBuf);
            ret_i--;
        }
        strnset(pageBuf, '\0', BUFSIZ);
    }

    char buf[1024];
    sscanf(str, "%*[^\"]\"%[^\"]", buf); //����httpͷ��ȡ��Կ
                                         //printf("%s", buf);
    closesocket(sock);
    WSACleanup();

    //д���ļ�
    FILE *fp;
    fp = fopen("Test", "w");//���ļ�
    if (fp == NULL)
    {
        printf("Error!\n��������д�����ԱȨ���Բ������ļ�����");//��ʧ��
        return -1;
    }
    fprintf(fp, "%s", buf);
    fclose(fp);//�ر����ͷ�ָ��

    return 0;
}