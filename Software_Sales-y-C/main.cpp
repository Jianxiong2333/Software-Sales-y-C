#include <stdio.h>
#include <io.h>
#include "Machinecode.h"//������
#include "Rsa.h"        //����
#include "Getapi.h"     //�ӿ�
#include "Md5.h"        //Md5
#include "CheckDebug.h" //������

#define Exit printf("\n��ǰ�����Ѿ���ɣ����ֶ���������鿴�Ƿ�ɹ�\n");//�˳�ʱ��������֪ͨ��

int main(void)
{
    char machine_code[170] = { 0 }; //������
    char encrypt[256] = { 0 };      //���ܺ�����
    char user_encrypt[256] = { 0 };         //�û����ؼ�������
    char user_email[64] = { 0 };            //�û����������
    char user_key[32] = { 0 };              //�û�����ļ�����(MD5)
    char decrypt[128] = { 0 };              //�û�������ܺ�����
    char user_get[512] = "xxx.xxx.xxx/proving.php?Key="; //������֤�ϴ��Ľӿ�
    char user_url[256] = "http://xx.xxx.xxx/index.php?Code=";//����ӿ�,http:// �������
    char user_url_api[256] = { 0 };         //������֤���ص�����
    char validate[256] = { 0 };             //��֤�û���������Ƿ���Ч
    FILE *fp;

    /*�����ԣ�����������ʱ��ע�ʹ˴����루�˴�ʾ��ֻ����ʾ��ʵ��������������Ҫ���мӿǼ��ܼӻ�����ֹ����/�ƽ⣩*/
    if (NtQueryInformationProcessApproach())//���ص���
    {
        printf("�����Ե��Դ˳���\n");//��⵽������
        if (CloseHandleException())
        {
            printf("CloseHandleException()���ս����\n");//�׳��쳣��������
        }
        if (AD_SetUnhandledExceptionFilter())//�׳��쳣��������
        {
            printf("AD_SetUnhandledExceptionFilter()���ս����\n");//�׳��쳣��������
        }
        abort();//�쳣��ֹ������ƽ����ƹ����������ƣ���ֹ����
    }

    /*��˽Կ������֤���Ͻ�һ����Ŀͬʱ�洢һ������ƥ��Ĺ�˽Կ�أ����뵥���ֱ�洢���׹�˽Կ��
    ˽Կ��ͨ�� OpenSSL ����汾���� genrsa -out private.key 1024�����ȣ�1024/2048�����ɣ�
    ��Կ��ͨ�� rsa -in private.key -pubout -out public.key ��˽Կ����ȡ��Կ��*/

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
    //���������ɹ�Կ����Ӧ���϶˽���˽Կ��
    const char *b64_pKey = "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMy7tL9tUK6F/63Uv9SM+mvCBt\n"
        "fov75HM0krNE36SI7bFXTEfPoG7AtsB9VMjU/GayE45muqwF4rVXhMz4zP2qVkVv\n"
        "iKSRKN0zkeK/aWQMgZI5/JuSZH64IezpOqnwzh+RHVn6DqDTFP8S83pHnISYMINQ\n"
        "s0uYXHqE63EVIIXDAQIDAQAB\n"
        "-----END PUBLIC KEY-----\n";

    //�ش���������ǩ˽Կ����Ӧ���ϼ��ܹ�Կ��
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

    /*��ȡ���ؼ�����*/
    if (access("Test", 0) != 0)//����ļ��Ƿ����
    {
        if ((fp = fopen("Test", "a+")) == NULL)
        {
            fclose(fp);
            printf("Error!\n��������д�����ԱȨ���Բ������ļ�����");//��ʧ��
            while (1)//ǿ���ڴ˴�ͣ������ֹ�˳��������������ϵ��⣬�����ƽ⸴�Ӷȡ�
            {
                ;
            }
            abort();//�쳣��ֹ������ƽ����ƹ����������ƣ���ֹ����
        }
        //�ļ��������򴴽��ļ�,��д�뱨������
        fprintf(fp, "%s", "n1XJ5dKk8whL7U85tERiZ4k0UiUdq+r/gxrAUMEP/fFaVdrI9pmFMAL0Yl2Sqc/aS/YCBuNFaRYlHY7rItlrze6HA/FvLiCR1AmGcX1BMmIrx8g5qlOScK5sX/PDacb5t8H7go1HY7Po3xuueiQS2r233XE+yHvewb1SQ4VHuqo=");
        fclose(fp);
    }
    if ((fp = fopen("Test", "a+")) == NULL)//��д�ļ�
    {
        fclose(fp);
        printf("Error!\n��������д�����ԱȨ���Բ������ļ�����");//��ʧ��
        while (1)//ǿ���ڴ˴�ͣ������ֹ�˳��������������ϵ��⣬�����ƽ⸴�Ӷȡ�
        {
            ;
        }
        abort();//�쳣��ֹ������ƽ����ƹ����������ƣ���ֹ����
    }
    fgets(user_encrypt, 256, fp);//��ȡ������
    fclose(fp);

    /*��ȡ������*/
    strcat_s(machine_code, sizeof(machine_code), Machinecode());    //Machinecode()���ɵĻ�����ԭ������ machine_code
                                                                    /*ͨ�����ؼ���������֤�Ƿ�ͨ��*/
    strcat_s(decrypt, sizeof(decrypt), Rsa_decrypt(user_encrypt, b64priv_key));//�������϶˷��صļ�����
    strcat_s(validate, sizeof(validate), "asdsad");                //ƴ�������
    strcat_s(validate, sizeof(validate), Getmd5_16(machine_code)); //ƴ��ժҪ������
    strcat_s(validate, sizeof(validate), "ACDSDA");                //ƴ���һ���
    if (strcmp(decrypt, Getmd5(validate)) != 0)                     //�ַ����Ƚ�
    {
        /*��⵽δ����*/

        /*���������*/
        strcat_s(encrypt, sizeof(encrypt), Rsa_encrypt(machine_code, b64_pKey));  //encrypt()���ܻ�����(����Ϊ���ļ���Կ)����� encrypt,

                                                                                  /*ƴ�ӹ�������*/
        strcat_s(user_url, sizeof(user_url), encrypt);

        /*չ�ּ��ܻ�����*/
        ShellExecute(NULL, _T("open"), (LPCWSTR)user_url, NULL, NULL, SW_SHOWNORMAL);//���ʹ�������
        printf("����ǰ�豸����δ����״̬�����Զ�Ϊ������Ȩ������վ������ע�ἤ�\n\n----------��δ���Զ�����վ�����ֶ��������¼���ƾ֤����Ȩҳ�湺��----------\n\n%s\n\n", encrypt);
        printf("----------�����ڴ���д��Ȩƾ֤������������ͨ�������Ի������������Ȩ----------\n\n������ƾ֤���䣨�����ǹ���ʱ��д�ģ���");
        scanf_s("%s", user_email, 64);  //���� 63λ�ڵ���������

        printf("�����뼤���루��ʷ��������������ѯҳ��鿴����");
        if ((scanf_s("%32s", user_key, 32) != 1) || strlen(user_key) != 19 || strlen(user_key) <= 4) //��������ִ��(��֤�ɿ����������������ȼ�)���������ַ�����Ƿ񳬹� 31 λ���ټ���Ƿ��� 20 λ��������Ϊ16λmd5�����Ϻ��Ϊ 19 λ�����ټ�������Ƿ�С����λ
        {
            /*��ǰ�û�ƾ֤�����ţ���ʾ������֤��ǿ�ƽ⸴�Ӷ�*/

            Exit//��ʾ����֪ͨ
                while (1)//ǿ���ڴ˴�ͣ������ֹ�˳��������������ϵ��⣬�����ƽ⸴�Ӷȡ�
                {
                    ;
                }
            abort();//�쳣��ֹ������ƽ����ƹ����������ƣ���ֹ����
        }
        else
        {
            /*������֤ͨ��������������֤*/
            //strcat_s(user_get, sizeof(user_get), Rsa_encrypt(user_key, b64_pKey)); //�ӿ�ƴ��md5,������
            strcat_s(user_get, sizeof(user_get), user_key);
            strcat_s(user_get, sizeof(user_get), "&Email=");  //ƴ��Email����
            strcat_s(user_get, sizeof(user_get), user_email); //ƴ��Emailֵ
            Getapi(user_get); //���ýӿ��ö��μ����뱣��������
            Exit//��ʾ����֪ͨ
                while (1)//ǿ���ڴ˴�ͣ������ֹ�˳��������������ϵ��⣬�����ƽ⸴�Ӷȡ�
                {
                    ;
                }
            abort();//�쳣��ֹ������ƽ����ƹ����������ƣ���ֹ����
        }
    }
    /*��⵽�Ѽ���*/
    system("cls");
    printf("�ǳ���л���ļ�������Ϊ���漤��汾\n");
    /*���������*/
    //strcat_s(decrypt, sizeof(decrypt), Rsa_decrypt(encrypt, b64priv_key));

    getchar();
    return 0;
}
