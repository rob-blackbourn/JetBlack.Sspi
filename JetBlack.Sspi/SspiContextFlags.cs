﻿using System;

namespace JetBlack.Sspi
{
    /// <summary>
    /// Flags for InitiateSecurityContext.
    /// </summary>
    /// <remarks>
    /// See the fContextReq parameter at 
    /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa375507(v=vs.85).aspx
    /// </remarks>
    [Flags]
    public enum SspiContextFlags
    {
        /// <summary>
        /// No additional attributes are provided.
        /// </summary>
        None = 0,

        /// <summary>
        /// ISC_REQ_DELEGATE
        /// 
        /// The server can use the context to authenticate to other servers as the client. The
        /// MutualAuth flag must be set for this flag to work. Valid for Kerberos. Ignore this flag for 
        /// constrained delegation.
        /// </summary>
        Delegate = 0x00000001,

        /// <summary>
        /// ISC_REQ_MUTUAL_AUTH
        /// 
        /// The mutual authentication policy of the service will be satisfied.
        /// *Caution* - This does not necessarily mean that mutual authentication is performed, only that
        /// the authentication policy of the service is satisfied. To ensure that mutual authentication is
        /// performed, query the context attributes after it is created.
        /// </summary>
        MutualAuth = 0x00000002,

        /// <summary>
        /// ISC_REQ_REPLAY_DETECT
        /// 
        /// Detect replayed messages that have been encoded by using the EncryptMessage or MakeSignature 
        /// message support functionality.
        /// </summary>
        ReplayDetect = 0x00000004,

        /// <summary>
        /// ISC_REQ_SEQUENCE_DETECT
        /// 
        /// Detect messages received out of sequence when using the message support functionality. 
        /// This flag implies all of the conditions specified by the Integrity flag - out-of-order sequence 
        /// detection can only be trusted if the integrity of any underlying sequence detection mechanism 
        /// in transmitted data can be trusted.
        /// </summary>
        SequenceDetect = 0x00000008,

        /// <summary>
        /// ISC_REQ_CONFIDENTIALITY
        /// 
        /// The context must protect data while in transit. Encrypt messages by using the EncryptMessage function.
        /// 
        /// Confidentiality is supported for NTLM with Microsoft Windows NT version 4.0, SP4 and later and with the Kerberos protocol in Microsoft Windows 2000 and later.
        /// </summary>
        Confidentiality = 0x00000010,

        /// <summary>
        /// ISC_REQ_USE_SESSION_KEY
        /// 
        /// A new session key must be negotiated.
        /// This value is supported only by the Kerberos security package.
        /// </summary>
        UseSessionKey = 0x00000020,

        /// <summary>
        /// ISC_REQ_ALLOCATE_MEMORY
        /// 
        /// The security package allocates output buffers for you. Buffers allocated by the security package have 
        /// to be released by the context memory management functions.
        /// </summary>
        AllocateMemory = 0x00000100,

        /// <summary>
        /// ISC_REQ_CONNECTION
        /// 
        /// The security context will not handle formatting messages. This value is the default for the Kerberos, 
        /// Negotiate, and NTLM security packages.
        /// </summary>
        Connection = 0x00000800,

        /// <summary>
        /// ISC_REQ_EXTENDED_ERROR
        /// 
        /// When errors occur, the remote party will be notified.
        /// </summary>
        /// <remarks>
        /// A client specifies InitExtendedError in InitializeSecurityContext
        /// and the server specifies AcceptExtendedError in AcceptSecurityContext. 
        /// </remarks>
        InitExtendedError = 0x00004000,

        /// <summary>
        /// When errors occur, the remote party will be notified.
        /// </summary>
        /// <remarks>
        /// A client specifies InitExtendedError in InitializeSecurityContext
        /// and the server specifies AcceptExtendedError in AcceptSecurityContext. 
        /// </remarks>
        AcceptExtendedError = 0x00008000,

        /// <summary>
        /// Support a stream-oriented connection. Provided by clients.
        /// </summary>
        InitStream = 0x00008000,

        /// <summary>
        /// Support a stream-oriented connection. Provided by servers.
        /// </summary>
        AcceptStream = 0x00010000,

        /// <summary>
        /// ISC_REQ_INTEGRITY
        /// 
        /// Sign messages and verify signatures by using the EncryptMessage and MakeSignature functions.
        /// Replayed and out-of-sequence messages will not be detected with the setting of this attribute.
        /// Set ReplayDetect and SequenceDetect also if these behaviors are desired.
        /// </summary>
        InitIntegrity = 0x00010000,


        /// <summary>
        /// Sign messages and verify signatures by using the EncryptMessage and MakeSignature functions.
        /// Replayed and out-of-sequence messages will not be detected with the setting of this attribute.
        /// Set ReplayDetect and SequenceDetect also if these behaviors are desired.
        /// </summary>
        AcceptIntegrity = 0x00020000,

        InitIdentify = 0x00020000,
        AcceptIdentify = 0x00080000,

        /// <summary>
        /// An Schannel provider connection is instructed to not authenticate the server automatically.
        /// </summary>
        InitManualCredValidation = 0x00080000,

        /// <summary>
        /// An Schannel provider connection is instructed to not authenticate the client automatically.
        /// </summary>
        InitUseSuppliedCreds = 0x00000080
    }
}
