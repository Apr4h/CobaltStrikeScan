using GetInjectedThreads.Enums;
using System;
using System.Runtime.InteropServices;


namespace GetInjectedThreads.Structs
{
    // Token Structs reference
    // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation


    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public Int32 PrivilegeCount;

        // https://docs.microsoft.com/en-us/dotnet/standard/native-interop/customize-struct-marshaling
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public PRIVILEGE_CONSTANT LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES label;
    }

    [StructLayout(LayoutKind.Sequential)]
    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_origin
    public struct TOKEN_ORIGIN
    {
        public LUID OriginatingLogonSession;
    }
}
