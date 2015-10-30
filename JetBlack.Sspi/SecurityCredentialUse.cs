namespace JetBlack.Sspi
{
    /// <summary>
    /// Flags for AcquireCredentialsHandle.
    /// </summary>
    /// <remarks>
    /// See the fCredentialUse at http://msdn.microsoft.com/en-us/library/windows/desktop/aa374712(v=vs.85).aspx.
    /// </remarks>
    public enum SecurityCredentialUse
    {
        /// <summary>
        /// SECPKG_CRED_INBOUND
        /// 
        /// Validate an incoming server credential. Inbound credentials might
        /// be validated by using an authenticating authority when
        /// InitializeSecurityContext (General) or AcceptSecurityContext (General)
        /// is called. If such an authority is not available, the function will
        /// fail and return SEC_E_NO_AUTHENTICATING_AUTHORITY. Validation is
        /// package specific.
        /// </summary>
        Inbound = 0x01,

        /// <summary>
        /// SECPKG_CRED_OUTBOUND
        /// 
        /// Allow a local client credential to prepare an outgoing token.
        /// </summary>
        Outbound = 0x2,

        /// <summary>
        /// SECPKG_CRED_BOTH
        /// 
        /// Validate an incoming credential or use a local credential to prepare
        /// an outgoing token. This flag enables both other flags. This flag is
        /// not valid with the Digest and Schannel SSPs.
        /// </summary>
        Both = Inbound | Outbound
    }
}
