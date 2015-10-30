namespace JetBlack.Sspi
{
    /// <summary>
    /// Flags for EncryptMessage.
    /// </summary>
    /// <remarks>
    /// See the fQOP parameter at 
    /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa375378(v=vs.85).aspx.
    /// </remarks>
    internal enum EncryptQualityOfProtection : uint
    {
        /// <summary>
        /// SECQOP_WRAP_NO_ENCRYPT
        /// 
        /// Produce a header or trailer but do not encrypt the message.
        /// Note: KERB_WRAP_NO_ENCRYPT has the same value and the same meaning.
        /// </summary>
        WrapNoEncrypt = 0x80000001,

        /// <summary>
        /// SECQOP_WRAP_OOB_DATA
        /// 
        /// Send an Schannel alert message. In this case, the pMessage parameter
        /// must contain a standard two-byte SSL/TLS event code. This value is
        /// supported only by the Schannel SSP.
        /// </summary>
        WrapOobData = 0x40000000
    }

    internal enum MakeSignatureQualityOfProtection : uint
    {
        None = 0
    }
}
