﻿using NUnit.Framework;

namespace JetBlack.Sspi.Test
{
    [TestFixture]
    public class SecurityCredentialFixture
    {
        [TestCase("Negotiate", SecurityCredentialUse.Inbound)]
        [TestCase("Negotiate", SecurityCredentialUse.Outbound)]
        [TestCase("NTLM", SecurityCredentialUse.Inbound)]
        [TestCase("NTLM", SecurityCredentialUse.Outbound)]
        [TestCase("Kerberos", SecurityCredentialUse.Inbound)]
        [TestCase("Kerberos", SecurityCredentialUse.Outbound)]
        public void ShouldAquireCredentials(string packageName, SecurityCredentialUse credentialUse)
        {
            var credential = new SecurityCredential(packageName, credentialUse);
            credential.Acquire();
            credential.Dispose();
        }
    }
}
