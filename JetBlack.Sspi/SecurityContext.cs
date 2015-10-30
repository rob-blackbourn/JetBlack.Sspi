using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace JetBlack.Sspi
{
    /// <summary>
    /// A wrapper around the SspiHandle structure specifically used as a security context handle.
    /// </summary>
    public class SecurityContext : SafeHandle
    {
        private static readonly IList<SecurityPackageInfo> PackageInfos;

        private readonly SecurityCredential _credential;
        private readonly SspiContextFlags _requestedContextFlags;
        private SspiContextFlags _receivedContextFlags;
        private SspiHandle _handle;

        static SecurityContext()
        {
            PackageInfos = SecurityPackageInfo.Enumerate();
        }

        public SecurityContext(SecurityCredential credential, SspiContextFlags contextFlags)
            : base(IntPtr.Zero, true)
        {
            _handle = new SspiHandle();
            _credential = credential;
            _requestedContextFlags = contextFlags;
        }

        public static SecurityContext Initialize(SecurityCredential credential, SspiContextFlags contextFlags, string servicePrincipalName, byte[] input, out byte[] output)
        {
            var context = new SecurityContext(credential, contextFlags);
            context.Initialize(servicePrincipalName, input, out output);
            return context;
        }

        public bool IsInitialized { get; private set; }

        public override bool IsInvalid
        {
            get { return IsClosed || _handle.IsZero; }
        }

        public void DecryptMessage(int messageLength, byte[] encryptedBytes, out byte[] decryptedBytes)
        {
            decryptedBytes = null;

            var encryptedMessage = new byte[messageLength];
            Array.Copy(encryptedBytes, 0, encryptedMessage, 0, messageLength);

            var securityTrailerLength = encryptedBytes.Length - messageLength;
            var securityTrailer = new byte[securityTrailerLength];
            Array.Copy(encryptedBytes, messageLength, securityTrailer, 0, securityTrailerLength);

            var buffers = new[]
            {
                new SecurityBuffer(encryptedBytes, SecurityBufferType.Data),
                new SecurityBuffer(securityTrailer, SecurityBufferType.Stream)
            };

            var descriptor = new SecurityBufferDescriptor(buffers);
            var contextAddRefSuccess = false;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                DangerousAddRef(ref contextAddRefSuccess);
            }
            catch (Exception ex)
            {
                if (contextAddRefSuccess)
                {
                    DangerousRelease();
                    contextAddRefSuccess = false;
                }

                if (!(ex is ObjectDisposedException))
                    throw;
            }
            finally
            {
                try
                {
                    uint quality;
                    var result = NativeMethods.DecryptMessage(ref _handle, ref descriptor, 0, out quality);
                    if (result != NativeMethods.SEC_E_OK)
                        throw Win32Exception.Create(result, "Unable to decrypt message.");

                    decryptedBytes = descriptor.ToByteArray();
                }
                finally
                {
                    descriptor.Free();
                }
            }
        }

        private void QueryBufferSizes(out SecurityPackageContextSizes sizes)
        {
            var contextAddRefSuccess = false;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                DangerousAddRef(ref contextAddRefSuccess);
            }
            catch (Exception ex)
            {
                if (contextAddRefSuccess)
                {
                    DangerousRelease();
                    contextAddRefSuccess = false;
                }

                if (!(ex is ObjectDisposedException))
                    throw;
            }
            finally
            {
                var result = NativeMethods.QueryContextAttributes(ref _handle, QueryContextAttributes.Sizes, out sizes);

                DangerousRelease();

                if (result != NativeMethods.SEC_E_OK)
                {
                    throw Win32Exception.Create(result, "Unable to get the query context attribute sizes.");
                }
            }
        }

        private string _authority;

        public string Authority
        {
            get
            {
                if (_authority == null)
                {
                    QueryContextString(QueryContextAttributes.Authority, out _authority);
                    if (_authority == null) _authority = string.Empty;
                }
                return _authority;
            }
        }

        private string _user;

        public string User
        {
            get
            {
                if (_user == null)
                {
                    QueryContextString(QueryContextAttributes.Names, out _user);
                    if (_user == null) _user = string.Empty;
                }
                return _user;
            }
        }

        private void QueryContextString(QueryContextAttributes attribute, out string names)
        {
            if (attribute != QueryContextAttributes.Names && attribute != QueryContextAttributes.Authority)
                throw new InvalidOperationException("Only names and authorities are strings");

            var contextAddRefSuccess = false;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                DangerousAddRef(ref contextAddRefSuccess);
            }
            catch (Exception ex)
            {
                if (contextAddRefSuccess)
                {
                    DangerousRelease();
                    contextAddRefSuccess = false;
                }

                if (!(ex is ObjectDisposedException))
                    throw;
            }
            finally
            {
                var ptr = new IntPtr();
                var result = NativeMethods.QueryContextAttributes(ref _handle, attribute, out ptr);

                DangerousRelease();

                if (result != NativeMethods.SEC_E_OK)
                    throw Win32Exception.Create(result, "Unable to get the query context attribute names.");

                names = Marshal.PtrToStringAuto(ptr);
            }
        }

        public void EncryptMessage(byte[] inBytes, out byte[] outBytes)
        {
            outBytes = null;

            var contextAddRefSuccess = false;
            SecurityPackageContextSizes sizes;
            QueryBufferSizes(out sizes);

            var buffers = new[]
            {
                new SecurityBuffer(new byte[sizes.SecurityTrailer], SecurityBufferType.Token),
                new SecurityBuffer(inBytes, SecurityBufferType.Data),
                new SecurityBuffer(new byte[sizes.BlockSize], SecurityBufferType.Padding)
            };

            var descriptor = new SecurityBufferDescriptor(buffers);

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                DangerousAddRef(ref contextAddRefSuccess);
            }
            catch (Exception ex)
            {
                if (contextAddRefSuccess)
                {
                    DangerousRelease();
                    contextAddRefSuccess = false;
                }

                if (!(ex is ObjectDisposedException))
                    throw;
            }
            finally
            {
                try
                {
                    var result = NativeMethods.EncryptMessage(ref _handle, EncryptQualityOfProtection.WrapNoEncrypt, ref descriptor, 0);

                    DangerousRelease();

                    if (result != NativeMethods.SEC_E_OK)
                        throw Win32Exception.Create(result, "Unable to encrypt message.");

                    outBytes = descriptor.ToByteArray();
                }
                finally
                {
                    descriptor.Free();
                }
            }
        }

        public void MakeSignature(byte[] inBytes, out byte[] outBytes)
        {
            outBytes = null;

            var contextAddRefSuccess = false;

            SecurityPackageContextSizes sizes;
            QueryBufferSizes(out sizes);

            var buffers = new[]
            {
                new SecurityBuffer(new byte[sizes.SecurityTrailer], SecurityBufferType.Token),
                new SecurityBuffer(inBytes, SecurityBufferType.Data),
                new SecurityBuffer(new byte[sizes.BlockSize], SecurityBufferType.Padding)
            };

            var descriptor = new SecurityBufferDescriptor(buffers);

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                DangerousAddRef(ref contextAddRefSuccess);
            }
            catch (Exception ex)
            {
                if (contextAddRefSuccess)
                {
                    DangerousRelease();
                    contextAddRefSuccess = false;
                }

                if (!(ex is ObjectDisposedException))
                    throw;
            }
            finally
            {
                try
                {
                    var result = NativeMethods.MakeSignature(ref _handle, MakeSignatureQualityOfProtection.None, ref descriptor, 0);

                    DangerousRelease();

                    if (result != NativeMethods.SEC_E_OK)
                        throw Win32Exception.Create(result, "Unable to encrypt message.");

                    outBytes = descriptor.ToByteArray();
                }
                finally
                {
                    descriptor.Free();
                }
            }
        }

        public void VerifySignature(byte[] inBytes, out byte[] outBytes)
        {
            bool contextAddRefSuccess = false;

            SecurityPackageContextSizes sizes;
            QueryBufferSizes(out sizes);

            var buffers = new[]
            {
                new SecurityBuffer(new byte[sizes.SecurityTrailer], SecurityBufferType.Token),
                new SecurityBuffer(inBytes, SecurityBufferType.Data),
                new SecurityBuffer(new byte[sizes.BlockSize], SecurityBufferType.Padding)
            };

            var descriptor = new SecurityBufferDescriptor(buffers);

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                DangerousAddRef(ref contextAddRefSuccess);
            }
            catch (Exception ex)
            {
                if (contextAddRefSuccess)
                {
                    DangerousRelease();
                    contextAddRefSuccess = false;
                }

                if (!(ex is ObjectDisposedException))
                    throw;
            }
            finally
            {
                try
                {
                    var status = NativeMethods.VerifySignature(ref _handle, ref descriptor, 0, MakeSignatureQualityOfProtection.None);

                    DangerousRelease();

                    switch ((long)status)
                    {
                        case NativeMethods.SEC_E_OK:
                            outBytes = descriptor.ToByteArray();
                            break;

                        case NativeMethods.SEC_E_OUT_OF_SEQUENCE:
                        case NativeMethods.SEC_E_MESSAGE_ALTERED:
                            outBytes = null;
                            break;

                        default:
                            throw Win32Exception.Create(status, "Unable to encrypt message.");
                    }
                }
                finally 
                {
                    descriptor.Free();
                }
            }
        }

        public void Initialize(string servicePrincipalName, byte[] inBytes, out byte[] outBytes)
        {
            outBytes = null;

            var outputBuffer = new SecurityBufferDescriptor((int)_credential.PackageInfo.MaxTokenSize);

            var credentialAddRefSuccess = false;
            var contextAddRefSuccess = false;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                _credential.DangerousAddRef(ref credentialAddRefSuccess);
                DangerousAddRef(ref contextAddRefSuccess);
            }
            catch (Exception ex)
            {
                if (credentialAddRefSuccess)
                {
                    _credential.DangerousRelease();
                    credentialAddRefSuccess = false;
                }
                if (contextAddRefSuccess)
                {
                    DangerousRelease();
                    contextAddRefSuccess = false;
                }

                if (!(ex is ObjectDisposedException))
                    throw;
            }
            finally
            {
                try
                {
                    uint result;
                    long timestamp;
                    var credentialHandle = _credential.Handle;
                    if (inBytes == null || inBytes.Length == 0)
                    {
                        result = NativeMethods.InitializeSecurityContext(
                            ref credentialHandle,
                            IntPtr.Zero,
                            servicePrincipalName,
                            _requestedContextFlags,
                            0,
                            DataRepresentation.Network,
                            IntPtr.Zero,
                            0,
                            ref _handle,
                            ref outputBuffer,
                            out _receivedContextFlags,
                            out timestamp);
                    }
                    else
                    {
                        var serverToken = new SecurityBufferDescriptor(inBytes);

                        try
                        {
                            result = NativeMethods.InitializeSecurityContext(
                                ref credentialHandle,
                                ref _handle,
                                servicePrincipalName,
                                _requestedContextFlags,
                                0,
                                DataRepresentation.Network,
                                ref serverToken,
                                0,
                                ref _handle,
                                ref outputBuffer,
                                out _receivedContextFlags,
                                out timestamp);
                        }
                        finally
                        {
                            serverToken.Free();
                        }
                    }

                    _credential.DangerousRelease();
                    DangerousRelease();

                    if (result != NativeMethods.SEC_E_OK && result != NativeMethods.SEC_I_CONTINUE_NEEDED)
                        throw Win32Exception.Create(result, "Unable to initialize security context.");

                    outBytes = outputBuffer.ToByteArray();
                    IsInitialized = result == NativeMethods.SEC_E_OK;
                }
                finally
                {
                    outputBuffer.Free();
                }
            }
        }

        public void AcceptToken(byte[] inBytes, out byte[] outBytes)
        {
            outBytes = null;

            var outputBuffer = new SecurityBufferDescriptor((int)_credential.PackageInfo.MaxTokenSize);

            var credentialAddRefSuccess = false;
            var contextAddRefSuccess = false;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                _credential.DangerousAddRef(ref credentialAddRefSuccess);
                DangerousAddRef(ref contextAddRefSuccess);
            }
            catch (Exception ex)
            {
                if (credentialAddRefSuccess)
                {
                    _credential.DangerousRelease();
                    credentialAddRefSuccess = false;
                }
                if (contextAddRefSuccess)
                {
                    DangerousRelease();
                    contextAddRefSuccess = false;
                }

                if (!(ex is ObjectDisposedException))
                    throw;
            }
            finally
            {
                try
                {
                    var flags = SspiContextFlags.MutualAuth;
                    var clientToken = new SecurityBufferDescriptor(inBytes);

                    uint result;
                    long timestamp;
                    var credentialHandle = _credential.Handle;
                    if (_handle.IsZero)
                    {
                        result = NativeMethods.AcceptSecurityContext(
                            ref credentialHandle,
                            IntPtr.Zero,
                            ref clientToken,
                            flags,
                            DataRepresentation.Network,
                            ref _handle,
                            ref outputBuffer,
                            out flags,
                            out timestamp);
                    }
                    else
                    {

                        try
                        {
                            result = NativeMethods.AcceptSecurityContext(
                                ref credentialHandle,
                                ref _handle,
                                ref clientToken,
                                flags,
                                DataRepresentation.Network,
                                ref _handle,
                                ref outputBuffer,
                                out flags,
                                out timestamp);
                        }
                        finally
                        {
                            clientToken.Free();
                        }
                    }

                    _credential.DangerousRelease();
                    DangerousRelease();

                    if (result != NativeMethods.SEC_E_OK && result != NativeMethods.SEC_I_CONTINUE_NEEDED)
                        throw Win32Exception.Create(result, "Unable to initialize security context.");

                    outBytes = outputBuffer.ToByteArray();
                    IsInitialized = result == NativeMethods.SEC_E_OK;
                }
                finally
                {
                    outputBuffer.Free();
                }
            }
        }

        // protected methods
        protected override bool ReleaseHandle()
        {
            return NativeMethods.DeleteSecurityContext(ref _handle) == 0;
        }

        // static methods
        private static int GetMaxTokenSize()
        {
            uint count = 0;
            var array = IntPtr.Zero;

            try
            {
                var packages = SecurityPackageInfo.Enumerate();

                var result = NativeMethods.EnumerateSecurityPackages(ref count, ref array);
                if (result != NativeMethods.SEC_E_OK)
                    return NativeMethods.MAX_TOKEN_SIZE;

                var current = new IntPtr(array.ToInt64());
                var size = Marshal.SizeOf(typeof(SecurityPackageInfo));
                for (var i = 0; i < count; ++i)
                {
                    var package = (SecurityPackageInfo)Marshal.PtrToStructure(current, typeof(SecurityPackageInfo));
                    if (package.Name != null && package.Name.Equals(SspiPackage.Kerberos.ToString(), StringComparison.InvariantCultureIgnoreCase))
                        return (int)package.MaxTokenSize;
                    current = new IntPtr(current.ToInt64() + size);
                }

                return NativeMethods.MAX_TOKEN_SIZE;
            }
            catch
            {
                return NativeMethods.MAX_TOKEN_SIZE;
            }
            finally
            {
                try
                {
                    NativeMethods.FreeContextBuffer(array);
                }
                catch
                { }
            }
        }
    }
}
