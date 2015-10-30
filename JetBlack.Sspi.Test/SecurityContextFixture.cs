using NUnit.Framework;

namespace JetBlack.Sspi.Test
{
    [TestFixture]
    public class SecurityContextFixture
    {
        [TestCase("Negotiate", SspiContextFlags.MutualAuth | SspiContextFlags.InitIdentify | SspiContextFlags.Confidentiality | SspiContextFlags.ReplayDetect | SspiContextFlags.SequenceDetect | SspiContextFlags.Connection | SspiContextFlags.Delegate)]
        public void Test(string packageName, SspiContextFlags contextFlags)
        {
            var package = SecurityPackageInfo.Query(packageName);

            var clientCredential = new SecurityCredential(package, SecurityCredentialUse.Outbound);
            clientCredential.Acquire();

            var serverCredential = new SecurityCredential(package, SecurityCredentialUse.Inbound);
            serverCredential.Acquire();

            var clientContext = new SecurityContext(clientCredential, contextFlags);
            var serverContext = new SecurityContext(serverCredential, contextFlags);

            byte[] clientToken;
            clientContext.Initialize(serverCredential.PrincipalName, null, out clientToken);

            while (true)
            {
                byte[] serverToken;
                serverContext.AcceptToken(clientToken, out serverToken);
                if (serverContext.IsInitialized && clientContext.IsInitialized)
                    break;

                clientContext.Initialize(serverCredential.PrincipalName, serverToken, out clientToken);
                if (clientContext.IsInitialized && serverContext.IsInitialized)
                    break;
            }

            clientContext.Dispose();
            serverContext.Dispose();

            clientCredential.Dispose();
            serverCredential.Dispose();
        }
    }
}
