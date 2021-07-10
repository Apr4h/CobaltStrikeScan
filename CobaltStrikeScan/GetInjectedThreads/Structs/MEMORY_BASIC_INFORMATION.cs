using GetInjectedThreads.Enums;
using System;


namespace GetInjectedThreads.Structs
{
    // MEMORY_BASIC_INFORMATION struct required for VirtualQueryEx - to read state and type fields
    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information

    public struct MEMORY_BASIC_INFORMATION64
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public MemoryBasicInformationProtection AllocationProtect;
        public int __alignment1;
        public UIntPtr RegionSize;
        public MemoryBasicInformationState State;
        public MemoryBasicInformationProtection Protect;
        public MemoryBasicInformationType Type;
        public int __alignment2;
    }

    public struct MEMORY_BASIC_INFORMATION32
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public MemoryBasicInformationProtection AllocationProtect;
        public IntPtr RegionSize;
        public MemoryBasicInformationState State;
        public MemoryBasicInformationProtection Protect;
        public MemoryBasicInformationType Type;
    }
}
