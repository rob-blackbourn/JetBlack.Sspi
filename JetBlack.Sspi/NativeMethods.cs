using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace JetBlack.Sspi
{
    internal static class NativeMethods
    {
        // public constants
        public const int MAX_TOKEN_SIZE = 12288;

        public const long SEC_E_OK = 0x0;
        public const long SEC_E_INSUFFICENT_MEMORY = 0x80090300;
        public const long SEC_E_INVALID_HANDLE = 0x80090301;
        public const long SEC_E_TARGET_UNKNOWN = 0x80090303;
        public const long SEC_E_INTERNAL_ERROR = 0x80090304;
        public const long SEC_E_SECPKG_NOT_FOUND = 0x80090305;
        public const long SEC_E_INVALID_TOKEN = 0x80090308;
        public const long SEC_E_QOP_NOT_SUPPORTED = 0x8009030A;
        public const long SEC_E_LOGON_DENIED = 0x8009030C;
        public const long SEC_E_UNKNOWN_CREDENTIALS = 0x8009030D;
        public const long SEC_E_NO_CREDENTIALS = 0x8009030E;
        public const long SEC_E_MESSAGE_ALTERED = 0x8009030F;
        public const long SEC_E_OUT_OF_SEQUENCE = 0x80090310;
        public const long SEC_E_NO_AUTHENTICATING_AUTHORITY = 0x80090311;
        public const long SEC_E_CONTEXT_EXPIRED = 0x80090317;
        public const long SEC_E_INCOMPLETE_MESSAGE = 0x80090318;
        public const long SEC_E_BUFFER_TOO_SMALL = 0x80090321;
        public const long SEC_E_CRYPTO_SYSTEM_INVALID = 0x80090337;

        public const long SEC_I_CONTINUE_NEEDED = 0x00090312;
        public const long SEC_I_CONTEXT_EXPIRED = 0x00090317;
        public const long SEC_I_RENEGOTIATE = 0x00090321;


        // public static methods
        /// <summary>
        /// Acquires the credentials handle.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="package">The package.</param>
        /// <param name="credentialUsage">The credential usage.</param>
        /// <param name="logonId">The logon id.</param>
        /// <param name="identity">The identity.</param>
        /// <param name="keyCallback">The key callback.</param>
        /// <param name="keyArgument">The key argument.</param>
        /// <param name="credentialHandle">The credential handle.</param>
        /// <param name="timestamp">The timestamp.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374712(v=vs.85).aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.Unicode, SetLastError = true, ThrowOnUnmappableChar = true)]
        public static extern uint AcquireCredentialsHandle(
            string principal,
            string package,
            SecurityCredentialUse credentialUsage,
            IntPtr logonId,
            AuthIdentity identity,
            int keyCallback,
            IntPtr keyArgument,
            ref SspiHandle credentialHandle,
            out long timestamp);

        /// <summary>
        /// Acquires the credentials handle.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="package">The package.</param>
        /// <param name="credentialUsage">The credential usage.</param>
        /// <param name="logonId">The logon id.</param>
        /// <param name="identity">The identity.</param>
        /// <param name="keyCallback">The key callback.</param>
        /// <param name="keyArgument">The key argument.</param>
        /// <param name="credentialHandle">The credential handle.</param>
        /// <param name="timestamp">The timestamp.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374712(v=vs.85).aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.Unicode, SetLastError = true, ThrowOnUnmappableChar = true)]
        public static extern uint AcquireCredentialsHandle(
            string principal,
            string package,
            SecurityCredentialUse credentialUsage,
            IntPtr logonId,
            IntPtr identity,
            int keyCallback,
            IntPtr keyArgument,
            ref SspiHandle credentialHandle,
            out long timestamp);

        /// <summary>
        /// Deletes the security context.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa375354(v=vs.85).aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.Auto, SetLastError = false)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public static extern uint DeleteSecurityContext(ref SspiHandle context);

        /// <summary>
        /// Decrypts the message.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="pMessage">The p message.</param>
        /// <param name="sequenceNumber">The sequence number.</param>
        /// <param name="quality">The quality.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa375211(v=vs.85).aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern uint DecryptMessage(ref SspiHandle context, ref SecurityBufferDescriptor pMessage, uint sequenceNumber, out uint quality);

        [DllImport("security.dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern uint MakeSignature(ref SspiHandle contextHandle, MakeSignatureQualityOfProtection qualityOfProtection, ref SecurityBufferDescriptor bufferDescriptor, uint sequenceNumber);

        [DllImport("security.dll", CharSet = CharSet.Auto, SetLastError = false)]
        internal static extern uint VerifySignature(ref SspiHandle contextHandle, ref SecurityBufferDescriptor bufferDescriptor, uint sequenceNumber, MakeSignatureQualityOfProtection qualityOfProtection);

        /// <summary>
        /// Encrypts the message.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="quality">The quality.</param>
        /// <param name="pMessage">The p message.</param>
        /// <param name="sequenceNumber">The sequence number.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa375378(v=vs.85).aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern uint EncryptMessage(ref SspiHandle context, EncryptQualityOfProtection quality, ref SecurityBufferDescriptor pMessage, uint sequenceNumber);

        /// <summary>
        /// Enumerates the security packages.
        /// </summary>
        /// <param name="numPackages">The pc packages.</param>
        /// <param name="securityPackageInfoArray">The pp package information.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/aa375397%28v=VS.85%29.aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern uint EnumerateSecurityPackages(ref uint numPackages, ref IntPtr securityPackageInfoArray);

        /// <summary>
        /// Frees the context buffer.
        /// </summary>
        /// <param name="contextBuffer">The context buffer.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/aa375416(v=vs.85).aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.None)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public static extern uint FreeContextBuffer(IntPtr contextBuffer);

        /// <summary>
        /// Frees the credentials handle.
        /// </summary>
        /// <param name="sspiHandle">The sspi handle.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa375417(v=vs.85).aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.None)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public static extern int FreeCredentialsHandle(ref SspiHandle sspiHandle);

        /// <summary>
        /// Initializes the security context.
        /// </summary>
        /// <param name="credentialHandle">The credential handle.</param>
        /// <param name="inContextPtr">The in context PTR.</param>
        /// <param name="targetName">Name of the target.</param>
        /// <param name="flags">The flags.</param>
        /// <param name="reserved1">The reserved1.</param>
        /// <param name="dataRepresentation">The data representation.</param>
        /// <param name="inputBuffer">The input buffer.</param>
        /// <param name="reserved2">The reserved2.</param>
        /// <param name="outContextHandle">The out context handle.</param>
        /// <param name="outputBuffer">The output buffer.</param>
        /// <param name="outAttributes">The out attributes.</param>
        /// <param name="timestamp">The timestamp.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa375506(v=vs.85).aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.Unicode, SetLastError = true, ThrowOnUnmappableChar = true)]
        public static extern uint InitializeSecurityContext(
            ref SspiHandle credentialHandle,
            IntPtr inContextPtr,
            string targetName,
            SspiContextFlags flags,
            int reserved1,
            DataRepresentation dataRepresentation,
            IntPtr inputBuffer,
            int reserved2,
            ref SspiHandle outContextHandle,
            ref SecurityBufferDescriptor outputBuffer,
            out SspiContextFlags outAttributes,
            out long timestamp);

        /// <summary>
        /// Initializes the security context.
        /// </summary>
        /// <param name="credentialHandle">The credential handle.</param>
        /// <param name="inContextHandle">The in context handle.</param>
        /// <param name="targetName">Name of the target.</param>
        /// <param name="flags">The flags.</param>
        /// <param name="reserved1">The reserved1.</param>
        /// <param name="dataRepresentation">The data representation.</param>
        /// <param name="inputBuffer">The input buffer.</param>
        /// <param name="reserved2">The reserved2.</param>
        /// <param name="outContext">The out context.</param>
        /// <param name="outputBuffer">The output buffer.</param>
        /// <param name="outAttributes">The out attributes.</param>
        /// <param name="timestamp">The timestamp.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa375506(v=vs.85).aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.Unicode, SetLastError = true, ThrowOnUnmappableChar = true)]
        public static extern uint InitializeSecurityContext(
            ref SspiHandle credentialHandle,
            ref SspiHandle inContextHandle,
            string targetName,
            SspiContextFlags flags,
            int reserved1,
            DataRepresentation dataRepresentation,
            ref SecurityBufferDescriptor inputBuffer,
            int reserved2,
            ref SspiHandle outContext,
            ref SecurityBufferDescriptor outputBuffer,
            out SspiContextFlags outAttributes,
            out long timestamp);

        [DllImport("security.dll", CharSet = CharSet.Unicode, SetLastError = true, ThrowOnUnmappableChar = true)]
        internal static extern uint AcceptSecurityContext(
            ref SspiHandle credentialHandle,
            IntPtr inContextPtr,
            ref SecurityBufferDescriptor inputBuffer,
            SspiContextFlags requestedAttribs,
            DataRepresentation dataRepresentation,
            ref SspiHandle outContext,
            ref SecurityBufferDescriptor outputBuffer,
            out SspiContextFlags outputAttribs,
            out long timestamp);

        [DllImport("security.dll", CharSet = CharSet.Unicode, SetLastError = true, ThrowOnUnmappableChar = true)]
        internal static extern uint AcceptSecurityContext(
            ref SspiHandle credentialHandle,
            ref SspiHandle inContextHandle,
            ref SecurityBufferDescriptor inputBuffer,
            SspiContextFlags requestedAttribs,
            DataRepresentation dataRepresentation,
            ref SspiHandle outContext,
            ref SecurityBufferDescriptor outputBuffer,
            out SspiContextFlags outputAttribs,
            out long timestamp);





        /// <summary>
        /// Queries the context attributes.
        /// </summary>
        /// <param name="inContextHandle">The in context handle.</param>
        /// <param name="attribute">The attribute.</param>
        /// <param name="sizes">The sizes.</param>
        /// <returns>A result code.</returns>
        /// <remarks>
        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa379326(v=vs.85).aspx
        /// </remarks>
        [DllImport("security.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern uint QueryContextAttributes(ref SspiHandle inContextHandle, QueryContextAttributes attribute, out SecurityPackageContextSizes sizes);

        [DllImport("security.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern uint QueryContextAttributes(ref SspiHandle inContextHandle, QueryContextAttributes attribute, out IntPtr names);

        [DllImport("security.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern uint QuerySecurityPackageInfo(string pszPackageName, out IntPtr ppPackageInfo);

        [DllImport("security.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern uint EnumerateSecurityPackages(ref int pcPackages, ref IntPtr ppPackageInfo);

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport("Security.dll", CharSet = CharSet.Unicode)]
        internal static extern uint QueryCredentialsAttributes(ref SspiHandle credentialHandle, QueryCredentialsAttribute attributeName, out IntPtr buffer);
    }
}
