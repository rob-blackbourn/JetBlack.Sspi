using System.Runtime.InteropServices;

namespace JetBlack.Sspi
{
    /// <summary>
    /// SEC_WINNT_AUTH_IDENTITY
    /// 
    /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa378664(v=vs.85).aspx
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal sealed class AuthIdentity
    {
        /// <summary>
        /// String containing the user name.
        /// </summary>
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Username;

        /// <summary>
        /// Number of characters in User, excluding the terminating NULL.
        /// </summary>
        public int UsernameLength;

        /// <summary>
        /// String containing the domain or workgroup name.
        /// </summary>
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Domain;

        /// <summary>
        /// Number of characters in Domain, excluding the terminating NULL.
        /// </summary>
        public int DomainLength;

        /// <summary>
        /// String containing the user's password in the domain or workgroup.
        /// </summary>
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Password;

        /// <summary>
        /// Number of characters in Password, excluding the terminating NULL.
        /// </summary>
        public int PasswordLength;

        /// <summary>
        /// Flags used to specify ANSI or UNICODE. Must be one of the following:
        /// </summary>
        public AuthIdentityFlag Flags;

        public AuthIdentity(string username, string password)
        {
            Username = null;
            UsernameLength = 0;
            if (!string.IsNullOrEmpty(username))
            {
                Username = username;
                UsernameLength = username.Length;
            }

            Password = null;
            PasswordLength = 0;

            if (!string.IsNullOrEmpty(password))
            {
                Password = password;
                PasswordLength = password.Length;
            }

            Domain = null;
            DomainLength = 0;

            Flags = AuthIdentityFlag.Unicode;
        }
    }
}
