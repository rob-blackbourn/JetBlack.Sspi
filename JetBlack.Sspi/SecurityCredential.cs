using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace JetBlack.Sspi
{
    public class SecurityCredential : SafeHandle
    {

        private SspiHandle _handle;
        public SspiHandle Handle { get { return _handle; } }

        public SecurityCredential(SecurityPackageInfo packageInfo, SecurityCredentialUse credentialUse)
            : base(IntPtr.Zero, true)
        {
            _handle = new SspiHandle();
            PackageInfo = packageInfo;
            CredentialUse = credentialUse;
        }

        public override bool IsInvalid
        {
            get { return IsClosed || Handle.IsZero; }
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.FreeCredentialsHandle(ref _handle) == 0;
        }

        public SecurityPackageInfo PackageInfo { get; private set; }
        public SecurityCredentialUse CredentialUse { get; private set; }

        private string _principalName;

        public string PrincipalName
        {
            get { return _principalName ?? (_principalName = GetPrincipalName()); }
        }

        public string GetPrincipalName()
        {
            var success = false;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                DangerousAddRef(ref success);

                var buffer = new IntPtr();
                try
                {
                    var status = NativeMethods.QueryCredentialsAttributes(ref _handle, QueryCredentialsAttribute.Names, out buffer);
                    if (status != 0)
                        throw Win32Exception.Create(status, "Failed to query principal name");

                    return buffer == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUni(buffer);
                }
                finally
                {
                    if (buffer != IntPtr.Zero)
                        NativeMethods.FreeContextBuffer(buffer);
                }
            }
            finally
            {
                if (success)
                    DangerousRelease();
            }
        }

        public DateTime Expiry { get; private set; }

        public void Acquire()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
            }
            finally
            {
                long timestamp;
                var result = NativeMethods.AcquireCredentialsHandle(null, PackageInfo.Name, CredentialUse, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, ref _handle, out timestamp);
                if (result != NativeMethods.SEC_E_OK)
                {
                    SetHandleAsInvalid();
                    throw Win32Exception.Create(result, "Unable to acquire credential.");
                }

                Expiry = timestamp.ToDateTime();
            }
        }

        public void Acquire(string username, string password)
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
            }
            finally
            {
                long timestamp;
                var authIdentity = new AuthIdentity(username, password);
                var result = NativeMethods.AcquireCredentialsHandle(null, PackageInfo.Name, CredentialUse, IntPtr.Zero, authIdentity, 0, IntPtr.Zero, ref _handle, out timestamp);
                if (result != NativeMethods.SEC_E_OK)
                {
                    SetHandleAsInvalid();
                    throw Win32Exception.Create(result, "Unable to acquire credential.");
                }

                Expiry = timestamp.ToDateTime();
            }
        }
    }
}
