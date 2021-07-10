namespace GetInjectedThreads
{
    public enum ThreadAccess : int
    {
        Terminate = 0x0001,
        SuspendResume = 0x0002,
        GetContext = 0x0008,
        SetContext = 0x0010,
        SetInformation = 0x0020,
        QueryInformation = 0x0040,
        SetThreadToken = 0x0080,
        Impersonate = 0x0100,
        DirectImpersonation = 0x0200,
        AllAccess = 0x001f0ffb
    }

    public enum ThreadInfoClass : int
    {
        ThreadQuerySetWin32StartAddress = 9
    }
}
