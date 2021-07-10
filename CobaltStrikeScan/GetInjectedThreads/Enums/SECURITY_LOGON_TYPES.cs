namespace GetInjectedThreads.Enums
{
    // https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-security_logon_type
    public enum SECURITY_LOGON_TYPES
    {
        System,
        UndefinedLogonType,
        Interactive,
        Network,
        Batch,
        Service,
        Proxy,
        Unlock,
        NetworkCleartext,
        NewCredentials,
        RemoteInteractive,
        CachedInteractive,
        CachedRemoteInteractive,
        CachedUnlock
    }
}
