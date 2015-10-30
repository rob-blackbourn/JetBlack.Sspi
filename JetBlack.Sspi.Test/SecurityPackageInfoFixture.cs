using NUnit.Framework;

namespace JetBlack.Sspi.Test
{
    [TestFixture]
    public class SecurityPackageInfoFixture
    {
        [TestCase("Kerberos")]
        public void QueryShouldSucceed(string name)
        {
            var package = SecurityPackageInfo.Query(name);
            Assert.AreEqual(name, package.Name);
        }

        [Test]
        public void QueryShouldFail()
        {
            Assert.Throws<Win32Exception>(() => SecurityPackageInfo.Query("###ERROR###"));
        }

        [Test]
        public void EnumerateShouldSucceed()
        {
            var packages = SecurityPackageInfo.Enumerate();
            Assert.Greater(packages.Count, 0);
        }
    }
}
