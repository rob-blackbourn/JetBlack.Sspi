﻿namespace JetBlack.Sspi
{
    /// <summary>
    /// Flag for the AuthIdentity structure.
    /// </summary>
    internal enum AuthIdentityFlag
    {
        /// <summary>
        /// SEC_WINNT_AUTH_IDENTITY_ANSI
        /// </summary>
        Ansi = 0x1,
        /// <summary>
        /// SEC_WINNT_AUTH_IDENTITY_UNICODE
        /// </summary>
        Unicode = 0x2
    }
}
