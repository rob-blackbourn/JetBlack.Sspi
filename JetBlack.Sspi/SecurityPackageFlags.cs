using System;

namespace JetBlack.Sspi
{
    [Flags]
    public enum SecurityPackageFlags : uint
    {
        /// <summary>
        /// SECPKG_FLAG_INTEGRITY
        /// 
        /// The security package supports the MakeSignature and VerifySignature functions.
        /// </summary>
        Integrity = 0x1,

        /// <summary>
        /// SECPKG_FLAG_PRIVACY 
        /// 
        /// The security package supports the EncryptMessage (General) and DecryptMessage (General) functions.
        /// </summary>
        Privacy = 0x2,

        /// <summary>
        /// SECPKG_FLAG_TOKEN_ONLY
        /// 
        /// The package is interested only in the security-token portion of messages, and will ignore any other buffers. This is a performance-related issue.
        /// </summary>
        TokenOnly = 0x4,

        /// <summary>
        /// SECPKG_FLAG_DATAGRAM
        /// 
        /// Supports datagram-style authentication. For more information, see SSPI Context Semantics.
        /// Important  The Microsoft Kerberos package does not support datagram contexts in user-to-user mode.
        /// </summary>
        Datagram = 0x8,

        /// <summary>
        /// SECPKG_FLAG_CONNECTION
        /// 
        /// Supports connection-oriented style authentication. For more information, see SSPI Context Semantics.
        /// </summary>
        Connection = 0x10,

        /// <summary>
        /// SECPKG_FLAG_MULTI_REQUIRED
        /// 
        /// Multiple legs are required for authentication.
        /// </summary>
        MultiRequired = 0x20,

        /// <summary>
        /// SECPKG_FLAG_CLIENT_ONLY
        /// 
        /// Server authentication support is not provided.
        /// </summary>
        ClientOnly = 0x40,

        /// <summary>
        /// SECPKG_FLAG_EXTENDED_ERROR 
        /// 
        /// Supports extended error handling. For more information, see Extended Error Information.
        /// </summary>
        ExtendedError = 0x80,

        /// <summary>
        /// SECPKG_FLAG_IMPERSONATION 
        /// 
        /// Supports Windows impersonation in server contexts.
        /// </summary>
        Impersonation = 0x100,

        /// <summary>
        /// SECPKG_FLAG_ACCEPT_WIN32_NAME 
        /// 
        /// Understands Windows principal and target names.
        /// </summary>
        Win32Name = 0x200,

        /// <summary>
        /// SECPKG_FLAG_STREAM 
        /// 
        /// Supports stream semantics. For more information, see SSPI Context Semantics.
        /// </summary>
        Stream = 0x400,

        /// <summary>
        /// SECPKG_FLAG_NEGOTIABLE 
        /// 
        /// Can be used by the Microsoft Negotiate security package.
        /// </summary>
        Negotiable = 0X800,

        /// <summary>
        /// SECPKG_FLAG_GSS_COMPATIBLE 
        /// 
        /// Supports GSS compatibility.
        /// </summary>
        GssCompatible = 0x1000,

        /// <summary>
        /// SECPKG_FLAG_LOGON 
        /// 
        /// Supports LsaLogonUser.
        /// </summary>
        Logon = 0x2000,

        /// <summary>
        /// SECPKG_FLAG_ASCII_BUFFERS 
        /// 
        /// Token buffers are in ASCII characters format.
        /// </summary>
        AsciiBuffers = 0x4000,

        /// <summary>
        /// SECPKG_FLAG_FRAGMENT 
        /// 
        /// Supports separating large tokens into smaller buffers so that applications can make repeated calls to InitializeSecurityContext (General) and AcceptSecurityContext (General) with the smaller buffers to complete authentication.
        /// </summary>
        Fragment = 0x8000,

        /// <summary>
        /// SECPKG_FLAG_MUTUAL_AUTH 
        /// 
        /// Supports mutual authentication.
        /// </summary>
        MutualAuth = 0x10000,

        /// <summary>
        /// SECPKG_FLAG_DELEGATION 
        /// 
        /// Supports delegation.
        /// </summary>
        Delegation = 0x20000,

        /// <summary>
        /// SECPKG_FLAG_READONLY_WITH_CHECKSUM 
        /// 
        /// The security package supports using a checksum instead of in-place encryption when calling the EncryptMessage function.
        /// </summary>
        ReadonlyWithChecksum = 0x40000,

        /// <summary>
        /// SECPKG_FLAG_RESTRICTED_TOKENS 
        /// 
        /// Supports callers with restricted tokens.
        /// </summary>
        RestrictedTokens = 0x80000,

        /// <summary>
        /// SECPKG_FLAG_NEGO_EXTENDER 
        /// 
        /// The security package extends the Microsoft Negotiate security package. There can be at most one package of this type.
        /// </summary>
        NegoExtender = 0x00100000,

        /// <summary>
        /// SECPKG_FLAG_NEGOTIABLE2 
        /// 
        /// This package is negotiated by the package of type SECPKG_FLAG_NEGO_EXTENDER.
        /// </summary>
        Negotiable2 = 0x00200000,

        /// <summary>
        /// SECPKG_FLAG_APPCONTAINER_PASSTHROUGH 
        /// 
        /// This package receives all calls from app container apps.
        /// </summary>
        AppcontainerPassthrough = 0x00400000,

        /// <summary>
        /// SECPKG_FLAG_APPCONTAINER_CHECKS 
        /// 
        /// This package receives calls from app container apps if one of the following checks succeeds.
        /// Caller has default credentials capability.
        /// The target is a proxy server.
        /// The caller has supplied credentials.
        /// </summary>
        AppcontainerChecks = 0x00800000
    }

    [Flags]
    public enum SecurityPackageCallFlags
    {
        /// <summary>
        /// SECPKG_CALLFLAGS_APPCONTAINER 
        /// 
        /// The caller is an app container.
        /// </summary>
        Appcontainer = 0x00000001,

        /// <summary>
        /// SECPKG_CALLFLAGS_AUTHCAPABLE 
        /// 
        /// The caller can use default credentials.
        /// </summary>
        Authcapable = 0x00000002,

        /// <summary>
        /// SECPKG_CALLFLAGS_FORCE_SUPPLIED 
        /// 
        /// The caller can only use supplied credentials.
        /// </summary>
        ForceSupplied = 0x00000004
    }
}
