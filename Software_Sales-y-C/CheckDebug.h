#pragma once
#include <windows.h>
#include <Winternl.h>//NtSetInformationThreadApproach，NtQueryInformationProcessApproach 需要此头
/*********************************************************************************
*Function:NtGlobalFlags                         //函数名称
*Description:查询进程环境块(PEB)                //函数功能，性能等的描述
*Calls:                                         //被本函数调用的函数清单
*Called By:                                     //调用本函数的清单
*Input:                                         //输入参数的说明，包括每个参数的作用、取值说明及参数间关系
*Output:                                        //输出参数的说明
*Return:返回true时检测到调试器，否则无调试器。  //函数返回值的说明
*Others:Z
NtGlobalFlag字段位于PEB(进程环境块)0x68的偏移处，//其他说明
64位机器则是在偏移0xBC位置.该字段的默认值为0。
当调试器正在运行时, 该字段会被设置为一个特定的值.
绕过这种检测的方法十分简单，调试时将其值置0即可，不建议使用。
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
*Function:IsDebuggerPresent                     //函数名称
*Description:查询进程环境块(PEB)IsDebugged标志。//函数功能，性能等的描述
*Calls:                                         //被本函数调用的函数清单
*Called By:                                     //调用本函数的清单
*Input:                                         //输入参数的说明，包括每个参数的作用、取值说明及参数间关系
*Output:                                        //输出参数的说明
*Return:返回非零时检测到调试器，否则无调试器。  //函数返回值的说明
*Others:破解方法同样调试时将其值置0即可         //其他说明
**********************************************************************************/
BOOL CheckDebug_Is()

{

    return IsDebuggerPresent();

}

/*********************************************************************************
*Function:CheckRemoteDebuggerPresent            //函数名称
*Description:查询进程环境块(PEB)IsDebugged标志。//函数功能，性能等的描述
*Calls:                                         //被本函数调用的函数清单
*Called By:                                     //调用本函数的清单
*Input:                                         //输入参数的说明，包括每个参数的作用、取值说明及参数间关系
*Output:                                        //输出参数的说明
*Return:返回非零时检测到调试器，否则无调试器。  //函数返回值的说明
*Others:它不仅可以探测系统其他进程是否被调试，  //其他说明
通过传递自身进程句柄还可以探测自身是否被调试。
同IsDebuggerPresent几乎一致。
**********************************************************************************/
BOOL CheckDebug_CRDP()
{
    BOOL ret;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &ret);
    return ret;
}

/*********************************************************************************
*Function:CheckDebug_rdtsc                      //函数名称
*Description:使用 rdtsc 指令的时钟检测。        //函数功能，性能等的描述
*Calls:                                         //被本函数调用的函数清单
*Called By:              		                //调用本函数的清单
*Input:                                         //输入参数的说明，包括每个参数的作用、取值说明及参数间关系
*Output:                                        //输出参数的说明
*Return:返回非零时检测到调试器，否则无调试器。  //函数返回值的说明
*Others:被调试时，进程的运行速度大大降低，      //其他说明
利用rdtsc指令(操作码0x0F31)，它返回至系统重新启动以来的时钟数，
并且将其作为一个64位的值存入EDX:EAX中。恶意代码运行两次rdtsc指令，
然后比较两次读取之间的差值。时间戳如果存在滞后，则可以认为存在调试器。
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
*Function:CheckDebug_0xCC                       //函数名称
*Description:触发调试器中断                     //函数功能，性能等的描述
*Calls:                                         //被本函数调用的函数清单
*Called By:                                     //调用本函数的清单
*Input:                                         //输入参数的说明，包括每个参数的作用、取值说明及参数间关系
*Output:                                        //输出参数的说明
*Return:返回非零时触发中断成功，否则无调试器。  //函数返回值的说明
*Others:因为调试器使用INT 3来设置软件断点，插入 //其他说明
0xCC(INT 3)欺骗调试器使其认为这些0xCC机器码是自己设置的断点。
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
*Function:AD_SetUnhandledExceptionFilter        //函数名称
*Description:异常-SetUnhandledExceptionFilter   //函数功能，性能等的描述
*Calls:                                         //被本函数调用的函数清单
*Called By:                                     //调用本函数的清单
*Input:                                         //输入参数的说明，包括每个参数的作用、取值说明及参数间关系
*Output:                                        //输出参数的说明
*Return:调试中将异常抛给调试器，否则无调试器。  //函数返回值的说明
*Others:已经通过测试，无调试器返回0             //其他说明
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
    //SetUnhandledExceptionFilter()来注册新的Top Level Exception Filter回调函数。
    //触发异常时，系统在前面没有处理异常的情况下，会调用Kernel32.dll中的
    //UnhandledExceptionFilter()函数。UnhandledExceptionFilter（)会利用
    //ntdll.dll中的NtQueryInformationProcess()来判断是否被调试，
    //若判断在被调试，异常给调试器（调试器无法处理异常，进程终止）。
    //若判断未被调试，则调用Top Level Exception Filter回调函数。
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
*Function:NtQueryInformationProcessApproach     //函数名称
*Description: 检查进程调试                      //函数功能，性能等的描述
*Calls:                                         //被本函数调用的函数清单
*Called By:                                     //调用本函数的清单
*Input:                                         //输入参数的说明，包括每个参数的作用、取值说明及参数间关系
*Output:                                        //输出参数的说明
*Return:进程被调试返回 -1 值端口，否则非。      //函数返回值的说明
*Others:已经通过测试，非公开函数。              //其他说明
它的第二个参数可以用来查询进程的调试端口，需要
使用LoadLibrary和GetProceAddress的方法获取调用地址
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
        printf("[ERROR NtQueryInformationProcessApproach] NtQueryInformationProcess failed\n");//调用失败
    else
        return debugPort == -1;

    return false;
}

/*********************************************************************************
*Function:CloseHandleException                  //函数名称
*Description: 仅在调试器下运行时产生无效句柄    //函数功能，性能等的描述
*Calls:                                         //被本函数调用的函数清单
*Called By:                                     //调用本函数的清单
*Input:                                         //输入参数的说明，包括每个参数的作用、取值说明及参数间关系
*Output:                                        //输出参数的说明
*Return:返回非零为调试器存在。                  //函数返回值的说明
*Others:已经通过测试，查找传递给CloseHandle()   //其他说明
的无效句柄。CloseHandle将自动终结程序
（调试器产生无效句柄）
**********************************************************************************/
BOOL CloseHandleException(void)
{
    HANDLE hInvalid = (HANDLE)0xDEADBEEF; // 无效句柄
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