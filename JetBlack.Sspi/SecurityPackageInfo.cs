using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace JetBlack.Sspi
{
    /// <summary>
    /// A SecPkgInfo structure.
    /// </summary>
    /// <remarks>
    /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa380104(v=vs.85).aspx
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityPackageInfo
    {
        public SecurityPackageFlags Capabilities;
        public ushort Version;
        public ushort RpcIdentifier;
        public uint MaxTokenSize;
        [MarshalAs(UnmanagedType.LPTStr)]
        public string Name;
        [MarshalAs(UnmanagedType.LPTStr)]
        public string Comment;

        public static SecurityPackageInfo Query(string name)
        {
            var ptr = IntPtr.Zero;
            try
            {
                var status = NativeMethods.QuerySecurityPackageInfo(name, out ptr);
                if (status != 0)
                    throw Win32Exception.Create(status, "Failed to get package \"" + name + "\".");
                var secPkgInfo = ptr.ToStructure<SecurityPackageInfo>();
                return secPkgInfo;
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NativeMethods.FreeContextBuffer(ptr);
            }
        }

        public static IList<SecurityPackageInfo> Enumerate()
        {
            var ptr = new IntPtr();
            try
            {
                var count = 0;
                var status = NativeMethods.EnumerateSecurityPackages(ref count, ref ptr);
                if (status != 0)
                    throw Win32Exception.Create(status, "Failed to get enumerate packages.");
                return ptr.ToEnumerable<SecurityPackageInfo>(count).ToArray();
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    NativeMethods.FreeContextBuffer(ptr);
            }
        }
    }
}
