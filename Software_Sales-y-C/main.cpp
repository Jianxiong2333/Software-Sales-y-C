#include <stdio.h>
#include <io.h>
#include "Machinecode.h"//机器码
#include "Rsa.h"        //加密
#include "Getapi.h"     //接口
#include "Md5.h"        //Md5
#include "CheckDebug.h" //反调试

#define Exit printf("\n当前激活已经完成，请手动重启软件查看是否成功\n");//退出时调用重启通知宏

int main(void)
{
    char machine_code[170] = { 0 }; //机器码
    char encrypt[256] = { 0 };      //加密后数据
    char user_encrypt[256] = { 0 };         //用户本地加密数据
    char user_email[64] = { 0 };            //用户输入的邮箱
    char user_key[32] = { 0 };              //用户输入的激活码(MD5)
    char decrypt[128] = { 0 };              //用户输入解密后数据
    char user_get[512] = "xxx.xxx.xxx/proving.php?Key="; //网络验证上传的接口
    char user_url[256] = "http://xx.xxx.xxx/index.php?Code=";//购买接口,http:// 必须存在
    char user_url_api[256] = { 0 };         //网络验证返回的数据
    char validate[256] = { 0 };             //验证用户输入的码是否有效
    FILE *fp;

    /*检测调试，编译器调试时请注释此处代码（此处示例只做演示，实际生产环境中需要自行加壳加密加花来阻止调试/破解）*/
    if (NtQueryInformationProcessApproach())//返回调试
    {
        printf("请勿尝试调试此程序\n");//检测到调试器
        if (CloseHandleException())
        {
            printf("CloseHandleException()已终结调试\n");//抛出异常给调试器
        }
        if (AD_SetUnhandledExceptionFilter())//抛出异常给调试器
        {
            printf("AD_SetUnhandledExceptionFilter()已终结调试\n");//抛出异常给调试器
        }
        abort();//异常终止，如果破解者绕过了上述限制，终止程序。
    }

    /*公私钥交替验证，严禁一个项目同时存储一套完整匹配的公私钥必，必须单独分别存储两套公私钥，
    私钥可通过 OpenSSL 编译版本输入 genrsa -out private.key 1024（长度，1024/2048）生成，
    公钥可通过 rsa -in private.key -pubout -out public.key 从私钥中提取公钥。*/

    // public key
    // http://srdevspot.blogspot.ca/2011/08/openssl-error0906d064pem.html
    //1. The file must contain:
    //-----BEGIN CERTIFICATE-----
    //on a separate line (i.e. it must be terminated with a newline).
    //2. Each line of "gibberish" must be 64 characters wide.
    //3. The file must end with:
    //-----END CERTIFICATE-----
    // YOUR PUBLIC KEY MUST CONTAIN NEWLINES.  If it doesn't (ie if you generated it with
    // something like
    // ssh-keygen -t rsa -C "you@example.com"
    // ) THEN YOU MUST INSERT NEWLINES EVERY 64 CHRS (just line it up with how I have it here
    // or with how the ssh-keygen private key is formatted by default)
    //机器码生成公钥，对应线上端解密私钥。
    const char *b64_pKey = "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMy7tL9tUK6F/63Uv9SM+mvCBt\n"
        "fov75HM0krNE36SI7bFXTEfPoG7AtsB9VMjU/GayE45muqwF4rVXhMz4zP2qVkVv\n"
        "iKSRKN0zkeK/aWQMgZI5/JuSZH64IezpOqnwzh+RHVn6DqDTFP8S83pHnISYMINQ\n"
        "s0uYXHqE63EVIIXDAQIDAQAB\n"
        "-----END PUBLIC KEY-----\n";

    //回传激活码验签私钥，对应线上加密公钥。
    // private key
    const char *b64priv_key = "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIICXgIBAAKBgQDTJegCqxzj5gX7u6Sql6BXXdiXPZFZLVwK3SCzinJAtnMfeHgK\n"
        "93yVPV6Uop11RF7okG7sPg+RsWT12ltW6862HDVUDdGvmPFLDohbtQsjyRxZH+UE\n"
        "q2M7yWW0DQiI+3WNKHLa/Y8pI/uHwVvSqqrYQZ/vK+QxQowBZbfRFBtR3wIDAQAB\n"
        "AoGBAIiEmLao9dvvzGyPTQ8zS+tQ9QoMN57F8h3gDRWobOikTljJpivJChbf//fw\n"
        "EAhS9V4+jElYcu6LGLDQxn+zpQjyNxmv3bHXzjbATzQsz8vNyQC4N3CljkSr6c8W\n"
        "qlWHQH+hWFtxxbd1X7nEyBIpIhRQ5WucBl7wTrULr7+7kTHRAkEA+y4XMAmVfOyR\n"
        "DxmD62EagyAaGVIqOoJylcCy3kWN/hrpFUO3a148Y7ZE9lU6iIcnxMzWTTXaOLNG\n"
        "070pITPY2QJBANczKSDxkS+fgKRR9IcIIVJH9+WUYGgyY2NMMwp90LHuR6Co81vC\n"
        "8s9qanDfzTamLci9GkyMHVltsBwgkH/ijXcCQQDV4H0mDkMXyGgML3HA70If/Sm7\n"
        "/davU3w2P4sO8LLjeA6YaLy509ggH4fBKPlaX5thW/nubLiQJzdb/GoVN4yhAkBe\n"
        "3hvkfPmvD9arGcH9gRUHa9iZqbZyWLw9uwrJNju5JL0I01ItApz92QDBb7fMvqdy\n"
        "VgLw+de6Y8N+MtDgv6PzAkEAjy2xe6m2lIQu/0NLe62KOReoIi5GJuMQMU9bj+oV\n"
        "2imp88OGtLE9Dd89zQtpr8mHo8b0v1TAR/CmveoW8e5oWw==\n"
        "-----END RSA PRIVATE KEY-----\n";

    /*读取本地激活码*/
    if (access("Test", 0) != 0)//检测文件是否存在
    {
        if ((fp = fopen("Test", "a+")) == NULL)
        {
            fclose(fp);
            printf("Error!\n请给软件读写或管理员权限以操作您的激活码");//打开失败
            while (1)//强制在此处停留，防止退出函数被调试器断点检测，增加破解复杂度。
            {
                ;
            }
            abort();//异常终止，如果破解者绕过了上述限制，终止程序。
        }
        //文件不存在则创建文件,并写入报错密文
        fprintf(fp, "%s", "n1XJ5dKk8whL7U85tERiZ4k0UiUdq+r/gxrAUMEP/fFaVdrI9pmFMAL0Yl2Sqc/aS/YCBuNFaRYlHY7rItlrze6HA/FvLiCR1AmGcX1BMmIrx8g5qlOScK5sX/PDacb5t8H7go1HY7Po3xuueiQS2r233XE+yHvewb1SQ4VHuqo=");
        fclose(fp);
    }
    if ((fp = fopen("Test", "a+")) == NULL)//读写文件
    {
        fclose(fp);
        printf("Error!\n请给软件读写或管理员权限以操作您的激活码");//打开失败
        while (1)//强制在此处停留，防止退出函数被调试器断点检测，增加破解复杂度。
        {
            ;
        }
        abort();//异常终止，如果破解者绕过了上述限制，终止程序。
    }
    fgets(user_encrypt, 256, fp);//读取激活码
    fclose(fp);

    /*获取机器码*/
    strcat_s(machine_code, sizeof(machine_code), Machinecode());    //Machinecode()生成的机器码原码后存入 machine_code
                                                                    /*通过本地激活码检测验证是否通过*/
    strcat_s(decrypt, sizeof(decrypt), Rsa_decrypt(user_encrypt, b64priv_key));//解密线上端返回的激活码
    strcat_s(validate, sizeof(validate), "asdsad");                //拼接左混淆
    strcat_s(validate, sizeof(validate), Getmd5_16(machine_code)); //拼接摘要机器码
    strcat_s(validate, sizeof(validate), "ACDSDA");                //拼接右混淆
    if (strcmp(decrypt, Getmd5(validate)) != 0)                     //字符串比较
    {
        /*检测到未激活*/

        /*机器码加密*/
        strcat_s(encrypt, sizeof(encrypt), Rsa_encrypt(machine_code, b64_pKey));  //encrypt()加密机器码(参数为明文及公钥)后存入 encrypt,

                                                                                  /*拼接购买链接*/
        strcat_s(user_url, sizeof(user_url), encrypt);

        /*展现加密机器码*/
        ShellExecute(NULL, _T("open"), (LPCWSTR)user_url, NULL, NULL, SW_SHOWNORMAL);//访问购买链接
        printf("您当前设备处于未激活状态，已自动为您打开授权购买网站，请您注册激活。\n\n----------若未打开自动打开网站，请手动复制如下激活凭证到授权页面购买----------\n\n%s\n\n", encrypt);
        printf("----------请您在此填写授权凭证，并保持网络通信正常以获得您的正版授权----------\n\n请输入凭证邮箱（必须是购买时填写的）：");
        scanf_s("%s", user_email, 64);  //允许 63位内的邮箱输入

        printf("请输入激活码（历史购买请在邮箱或查询页面查看）：");
        if ((scanf_s("%32s", user_key, 32) != 1) || strlen(user_key) != 19 || strlen(user_key) <= 4) //从左至右执行(保证可靠，用括号提升优先级)，先输入字符检测是否超过 31 位，再检测是否不足 20 位（激活码为16位md5，加上横杠为 19 位），再检测邮箱是否小于四位
        {
            /*当前用户凭证不可信，提示重启验证增强破解复杂度*/

            Exit//显示重启通知
                while (1)//强制在此处停留，防止退出函数被调试器断点检测，增加破解复杂度。
                {
                    ;
                }
            abort();//异常终止，如果破解者绕过了上述限制，终止程序。
        }
        else
        {
            /*初步验证通过，进行网络验证*/
            //strcat_s(user_get, sizeof(user_get), Rsa_encrypt(user_key, b64_pKey)); //接口拼接md5,并加密
            strcat_s(user_get, sizeof(user_get), user_key);
            strcat_s(user_get, sizeof(user_get), "&Email=");  //拼接Email参数
            strcat_s(user_get, sizeof(user_get), user_email); //拼接Email值
            Getapi(user_get); //调用接口让二次激活码保存至本地
            Exit//显示重启通知
                while (1)//强制在此处停留，防止退出函数被调试器断点检测，增加破解复杂度。
                {
                    ;
                }
            abort();//异常终止，如果破解者绕过了上述限制，终止程序。
        }
    }
    /*检测到已激活*/
    system("cls");
    printf("非常感谢您的激活，此软件为正版激活版本\n");
    /*机器码解密*/
    //strcat_s(decrypt, sizeof(decrypt), Rsa_decrypt(encrypt, b64priv_key));

    getchar();
    return 0;
}
