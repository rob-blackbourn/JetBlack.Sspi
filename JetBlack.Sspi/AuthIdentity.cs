using System;
using System.Runtime.InteropServices;

namespace JetBlack.Sspi
{
    /// <summary>
    /// SEC_WINNT_AUTH_IDENTITY
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal sealed class AuthIdentity
    {
        // public fields
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Username;
        public int UsernameLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Domain;
        public int DomainLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Password;
        public int PasswordLength;
        public AuthIdentityFlag Flags;

        // constructors
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
