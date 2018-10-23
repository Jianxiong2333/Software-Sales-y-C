#pragma once
#include <windows.h>
#include <Winternl.h>//NtSetInformationThreadApproach��NtQueryInformationProcessApproach ��Ҫ��ͷ
/*********************************************************************************
*Function:NtGlobalFlags                         //��������
*Description:��ѯ���̻�����(PEB)                //�������ܣ����ܵȵ�����
*Calls:                                         //�����������õĺ����嵥
*Called By:                                     //���ñ��������嵥
*Input:                                         //���������˵��������ÿ�����������á�ȡֵ˵�����������ϵ
*Output:                                        //���������˵��
*Return:����trueʱ��⵽�������������޵�������  //��������ֵ��˵��
*Others:Z
NtGlobalFlag�ֶ�λ��PEB(���̻�����)0x68��ƫ�ƴ���//����˵��
64λ����������ƫ��0xBCλ��.���ֶε�Ĭ��ֵΪ0��
����������������ʱ, ���ֶλᱻ����Ϊһ���ض���ֵ.
�ƹ����ּ��ķ���ʮ�ּ򵥣�����ʱ����ֵ��0���ɣ�������ʹ�á�
**********************************************************************************/
bool NtGlobalFlags()
{
    __asm
    {
        mov eax, fs:[30h]
        mov eax, [eax + 68h]
        and eax, 0x70
        test eax, eax
        jne rt_label
        jmp rf_label
    }
rt_label:
    return true;
rf_label:
    return false;
}

/*********************************************************************************
*Function:IsDebuggerPresent                     //��������
*Description:��ѯ���̻�����(PEB)IsDebugged��־��//�������ܣ����ܵȵ�����
*Calls:                                         //�����������õĺ����嵥
*Called By:                                     //���ñ��������嵥
*Input:                                         //���������˵��������ÿ�����������á�ȡֵ˵�����������ϵ
*Output:                                        //���������˵��
*Return:���ط���ʱ��⵽�������������޵�������  //��������ֵ��˵��
*Others:�ƽⷽ��ͬ������ʱ����ֵ��0����         //����˵��
**********************************************************************************/
BOOL CheckDebug_Is()

{

    return IsDebuggerPresent();

}

/*********************************************************************************
*Function:CheckRemoteDebuggerPresent            //��������
*Description:��ѯ���̻�����(PEB)IsDebugged��־��//�������ܣ����ܵȵ�����
*Calls:                                         //�����������õĺ����嵥
*Called By:                                     //���ñ��������嵥
*Input:                                         //���������˵��������ÿ�����������á�ȡֵ˵�����������ϵ
*Output:                                        //���������˵��
*Return:���ط���ʱ��⵽�������������޵�������  //��������ֵ��˵��
*Others:����������̽��ϵͳ���������Ƿ񱻵��ԣ�  //����˵��
ͨ������������̾��������̽�������Ƿ񱻵��ԡ�
ͬIsDebuggerPresent����һ�¡�
**********************************************************************************/
BOOL CheckDebug_CRDP()
{
    BOOL ret;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &ret);
    return ret;
}

/*********************************************************************************
*Function:CheckDebug_rdtsc                      //��������
*Description:ʹ�� rdtsc ָ���ʱ�Ӽ�⡣        //�������ܣ����ܵȵ�����
*Calls:                                         //�����������õĺ����嵥
*Called By:              		                //���ñ��������嵥
*Input:                                         //���������˵��������ÿ�����������á�ȡֵ˵�����������ϵ
*Output:                                        //���������˵��
*Return:���ط���ʱ��⵽�������������޵�������  //��������ֵ��˵��
*Others:������ʱ�����̵������ٶȴ�󽵵ͣ�      //����˵��
����rdtscָ��(������0x0F31)����������ϵͳ��������������ʱ������
���ҽ�����Ϊһ��64λ��ֵ����EDX:EAX�С����������������rdtscָ�
Ȼ��Ƚ����ζ�ȡ֮��Ĳ�ֵ��ʱ�����������ͺ��������Ϊ���ڵ�������
**********************************************************************************/
BOOL CheckDebug_rdtsc()
{
    DWORD time1, time2;
    __asm
    {
        rdtsc
        mov time1, eax
        rdtsc
        mov time2, eax
    }
    if (time2 - time1 < 0xff)
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

/*********************************************************************************
*Function:CheckDebug_0xCC                       //��������
*Description:�����������ж�                     //�������ܣ����ܵȵ�����
*Calls:                                         //�����������õĺ����嵥
*Called By:                                     //���ñ��������嵥
*Input:                                         //���������˵��������ÿ�����������á�ȡֵ˵�����������ϵ
*Output:                                        //���������˵��
*Return:���ط���ʱ�����жϳɹ��������޵�������  //��������ֵ��˵��
*Others:��Ϊ������ʹ��INT 3����������ϵ㣬���� //����˵��
0xCC(INT 3)��ƭ������ʹ����Ϊ��Щ0xCC���������Լ����õĶϵ㡣
**********************************************************************************/
BOOL CheckDebug_0xCC()
{
    __try
    {
        __asm int 3
    }
    __except (1)
    {
        return FALSE;
    }
    return TRUE;
}

/*********************************************************************************
*Function:AD_SetUnhandledExceptionFilter        //��������
*Description:�쳣-SetUnhandledExceptionFilter   //�������ܣ����ܵȵ�����
*Calls:                                         //�����������õĺ����嵥
*Called By:                                     //���ñ��������嵥
*Input:                                         //���������˵��������ÿ�����������á�ȡֵ˵�����������ϵ
*Output:                                        //���������˵��
*Return:�����н��쳣�׸��������������޵�������  //��������ֵ��˵��
*Others:�Ѿ�ͨ�����ԣ��޵���������0             //����˵��
**********************************************************************************/
LPVOID g_pOrgFilter = 0;

LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS pExcept)
{
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)g_pOrgFilter);

    // 8900    MOV DWORD PTR DS:[EAX], EAX
    // FFE0    JMP EAX
    pExcept->ContextRecord->Eip += 4;

    return EXCEPTION_CONTINUE_EXECUTION;
}
BOOL AD_SetUnhandledExceptionFilter()
{
    //SetUnhandledExceptionFilter()��ע���µ�Top Level Exception Filter�ص�������
    //�����쳣ʱ��ϵͳ��ǰ��û�д����쳣������£������Kernel32.dll�е�
    //UnhandledExceptionFilter()������UnhandledExceptionFilter��)������
    //ntdll.dll�е�NtQueryInformationProcess()���ж��Ƿ񱻵��ԣ�
    //���ж��ڱ����ԣ��쳣�����������������޷������쳣��������ֹ����
    //���ж�δ�����ԣ������Top Level Exception Filter�ص�������
    g_pOrgFilter = (LPVOID)SetUnhandledExceptionFilter(
        (LPTOP_LEVEL_EXCEPTION_FILTER)ExceptionFilter);

    __asm {
        xor eax, eax;
        mov dword ptr[eax], eax
            jmp eax
    }
    return FALSE;
}

/*********************************************************************************
*Function:NtQueryInformationProcessApproach     //��������
*Description: �����̵���                      //�������ܣ����ܵȵ�����
*Calls:                                         //�����������õĺ����嵥
*Called By:                                     //���ñ��������嵥
*Input:                                         //���������˵��������ÿ�����������á�ȡֵ˵�����������ϵ
*Output:                                        //���������˵��
*Return:���̱����Է��� -1 ֵ�˿ڣ�����ǡ�      //��������ֵ��˵��
*Others:�Ѿ�ͨ�����ԣ��ǹ���������              //����˵��
���ĵڶ�����������������ѯ���̵ĵ��Զ˿ڣ���Ҫ
ʹ��LoadLibrary��GetProceAddress�ķ�����ȡ���õ�ַ
**********************************************************************************/
typedef NTSTATUS(WINAPI *NtQueryInformationProcessPtr)(
    HANDLE processHandle,
    PROCESSINFOCLASS processInformationClass,
    PVOID processInformation,
    ULONG processInformationLength,
    PULONG returnLength);

bool NtQueryInformationProcessApproach()

{
    int debugPort = 0;

    HMODULE hModule = LoadLibrary(TEXT("Ntdll.dll "));
    NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hModule, "NtQueryInformationProcess");

    if (NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), NULL))
        printf("[ERROR NtQueryInformationProcessApproach] NtQueryInformationProcess failed\n");//����ʧ��
    else
        return debugPort == -1;

    return false;
}

/*********************************************************************************
*Function:CloseHandleException                  //��������
*Description: ���ڵ�����������ʱ������Ч���    //�������ܣ����ܵȵ�����
*Calls:                                         //�����������õĺ����嵥
*Called By:                                     //���ñ��������嵥
*Input:                                         //���������˵��������ÿ�����������á�ȡֵ˵�����������ϵ
*Output:                                        //���������˵��
*Return:���ط���Ϊ���������ڡ�                  //��������ֵ��˵��
*Others:�Ѿ�ͨ�����ԣ����Ҵ��ݸ�CloseHandle()   //����˵��
����Ч�����CloseHandle���Զ��ս����
��������������Ч�����
**********************************************************************************/
BOOL CloseHandleException(void)
{
    HANDLE hInvalid = (HANDLE)0xDEADBEEF; // ��Ч���
    DWORD found = FALSE;

    __try
    {
        CloseHandle(hInvalid);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = TRUE;
    }

    if (found)
    {
        return TRUE;
    }
    else
        return FALSE;
}