using System;
using System.Runtime.Serialization;

namespace JetBlack.Sspi
{
    /// <summary>
    /// Thrown from a win32 wrapped operation.
    /// </summary>
    [Serializable]
    public class Win32Exception : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Win32Exception" /> class.
        /// </summary>
        /// <param name="errorCode">The error code.</param>
        public Win32Exception(long errorCode)
        {
            HResult = (int)errorCode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Win32Exception" /> class.
        /// </summary>
        /// <param name="errorCode">The error code.</param>
        /// <param name="message">The message.</param>
        public Win32Exception(long errorCode, string message)
            : base(message)
        {
            HResult = (int)errorCode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Win32Exception" /> class.
        /// </summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
        protected Win32Exception(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        /// <summary>
        /// Creates an exception for the specified error code.
        /// </summary>
        /// <param name="errorCode">The error code.</param>
        /// <param name="defaultMessage">The default message.</param>
        /// <returns></returns>
        public static Win32Exception Create(long errorCode, string defaultMessage)
        {
            string message = defaultMessage;
            switch (errorCode)
            {
                case NativeMethods.SEC_E_BUFFER_TOO_SMALL:
                    message = "The message buffer is too small. Used with the Digest SSP.";
                    break;
                case NativeMethods.SEC_E_CONTEXT_EXPIRED:
                    message = "The application is referencing a context that has already been closed.";
                    break;
                case NativeMethods.SEC_E_CRYPTO_SYSTEM_INVALID:
                    message = "The cipher chosen for the security context is not supported. Used with the Digest SSP.";
                    break;
                case NativeMethods.SEC_E_INCOMPLETE_MESSAGE:
                    message = "The data in the input buffer is incomplete.";
                    break;
                case NativeMethods.SEC_E_INSUFFICENT_MEMORY:
                    message = "There is not enough memory available to complete the requested action.";
                    break;
                case NativeMethods.SEC_E_INTERNAL_ERROR:
                    message = "An error occurred that did not map to an SSPI error code.";
                    break;
                case NativeMethods.SEC_E_INVALID_HANDLE:
                    message = "The handle passed to the function is not valid.";
                    break;
                case NativeMethods.SEC_E_INVALID_TOKEN:
                    message = "The input token is malformed . Possible causes include a token corrupted in transit, a token of incorrect size, and a token passed into the wrong security package. This last condition can happen if the client and server did not negotiate the proper security package.";
                    break;
                case NativeMethods.SEC_E_LOGON_DENIED:
                    message = "The logon failed.";
                    break;
                case NativeMethods.SEC_E_MESSAGE_ALTERED:
                    message = "The message has been altered. Used with the Digest and Schannel SSPs.";
                    break;
                case NativeMethods.SEC_E_NO_AUTHENTICATING_AUTHORITY:
                    message = "No authority could be contacted for authentication. The domain name of the authenticating party could be wrong, the domain could be unreachable, or there might have been a trust relationship failure.";
                    break;
                case NativeMethods.SEC_E_NO_CREDENTIALS:
                    message = "No credentials are available in the security package.";
                    break;
                case NativeMethods.SEC_E_OUT_OF_SEQUENCE:
                    message = "The message was not received in the correct sequence.";
                    break;
                case NativeMethods.SEC_E_QOP_NOT_SUPPORTED:
                    message = "Neither confidentiality nor integrity are supported by the security context. Used with the Digest SSP.";
                    break;
                case NativeMethods.SEC_E_SECPKG_NOT_FOUND:
                    message = "The requested security package does not exist.";
                    break;
                case NativeMethods.SEC_E_TARGET_UNKNOWN:
                    message = "The target was not recognized.";
                    break;
                case NativeMethods.SEC_E_UNKNOWN_CREDENTIALS:
                    message = "The credentials supplied to the package were not recognized.";
                    break;
                case NativeMethods.SEC_I_CONTEXT_EXPIRED:
                    message = "The message sender has finished using the connection and has initiated a shutdown.";
                    break;
                case NativeMethods.SEC_I_RENEGOTIATE:
                    message = "The remote party requires a new handshake sequence or the application has just initiated a shutdown.";
                    break;
            }

            return new Win32Exception(errorCode, message);
        }
    }
}
