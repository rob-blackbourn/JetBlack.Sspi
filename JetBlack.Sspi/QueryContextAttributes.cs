namespace JetBlack.Sspi
{
    /// <summary>
    /// Flags for QueryContextAttributes.
    /// </summary>
    /// <remarks>
    /// See the ulAttribute parameter at 
    /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa379326(v=vs.85).aspx.
    /// </remarks>
    internal enum QueryContextAttributes
    {
        /// <summary>
        /// SECPKG_ATTR_SIZES
        /// 
        /// Queries the buffer size parameters when performing message functions, such
        /// as encryption, decryption, signing and signature validation.
        /// </summary>
        /// <remarks>
        /// Results for a query of this type are stored in a Win32 SecPkgContext_Sizes structure.
        /// </remarks>
        Sizes = 0,

        /// <summary>
        /// Queries the context for the name of the user assocated with a security context.
        /// </summary>
        /// <remarks>
        /// Results for a query of this type are stored in a Win32 SecPkgContext_Name structure.
        /// </remarks>
        Names = 1,

        /// <summary>
        /// Queries the name of the authenticating authority for the security context.
        /// </summary>
        /// <remarks>
        /// Results for a query of this type are stored in a Win32 SecPkgContext_Authority structure.
        /// </remarks>
        Authority = 6,
    }
}
