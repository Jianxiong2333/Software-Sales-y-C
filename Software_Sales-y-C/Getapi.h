#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#define BUFSIZ 1024 //缓冲区必须更改到这么大
#include <windows.h>

//套接字
int Getapi(char *url)
{
    /***********解析URL，解析出主机名，资源名**********/
    char host[BUFSIZ];
    char resource[BUFSIZ];
    char myurl[BUFSIZ];
    char *pHost = 0;
    if (strlen(url) > 2000)
    {
        return 0;
    }

    //解析出主机和资源名
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


    /*****************创建socket************/
    //初始化套接字
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //创建套接字
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        //printf("Failed socket().\n");
        printf("调用套接字出错.\n");
        WSACleanup();
        return 0;
    }

    //设置socket参数
    struct sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(80);

    //获取主机名和地址信息
    struct hostent *hp = gethostbyname(host);
    if (hp == NULL)
    {
        //printf("Can not find host address.\n");
        //找不到主机地址
        return 0;
    }
    sockAddr.sin_addr.s_addr = *((unsigned long *)hp->h_addr);

    //连接到服务器
    if (connect(sock, (SOCKADDR *)&sockAddr, sizeof(sockAddr)) == -1)
    {
        //printf("Failed connect().\n");
        printf("调用 connect().连接服务器失败\n");
        WSACleanup();
        return 0;
    }


    /****************与服务器通信，收发数据***************/
    //准备发送数据
    char request[BUFSIZ] = "";
    //request = "GET " + resource + " HTTP/1.1\r\nHost:" + host + "\r\nConnection:Close\r\n\r\n";
    strcat(request, "GET ");
    strcat(request, resource);
    strcat(request, " HTTP/1.1\r\nHost:");
    strcat(request, host);
    strcat(request, "\r\nConnection:Close\r\n\r\n");

    //发送数据
    if (SOCKET_ERROR == send(sock, request, sizeof(request), 0))
    {
        printf("Send error.\n");
        closesocket(sock);
        return 0;
    }

    //接收数据
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
    sscanf(str, "%*[^\"]\"%[^\"]", buf); //抛弃http头提取密钥
                                         //printf("%s", buf);
    closesocket(sock);
    WSACleanup();

    //写入文件
    FILE *fp;
    fp = fopen("Test", "w");//打开文件
    if (fp == NULL)
    {
        printf("Error!\n请给软件读写或管理员权限以操作您的激活码");//打开失败
        return -1;
    }
    fprintf(fp, "%s", buf);
    fclose(fp);//关闭流释放指针

    return 0;
}