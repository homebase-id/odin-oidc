using System.Net;
using Odin.Oidc.Login.Registration;

namespace Odin.Oidc.Login.Tests;

/// <summary>Where a client document may be fetched from: never a special-use address (RFC 6890), the draft's SSRF rule.</summary>
[TestFixture]
public class SafeAddressTests
{
    [TestCase("127.0.0.1")]
    [TestCase("::1")]
    [TestCase("10.1.2.3")]
    [TestCase("172.30.0.5")]
    [TestCase("192.168.1.1")]
    [TestCase("169.254.169.254")]
    [TestCase("100.64.0.1")]
    [TestCase("0.0.0.0")]
    [TestCase("224.0.0.1")]
    [TestCase("fe80::1")]
    [TestCase("fc00::1")]
    [TestCase("::ffff:10.0.0.1")]
    public void SpecialUseAddressesAreNeverFetched(string address)
    {
        Assert.That(SafeAddress.IsPublic(IPAddress.Parse(address)), Is.False);
    }

    [TestCase("203.0.113.7")]
    [TestCase("65.21.248.203")]
    [TestCase("2a01:4f9:c012:8a7a::1")]
    public void PublicAddressesAre(string address)
    {
        Assert.That(SafeAddress.IsPublic(IPAddress.Parse(address)), Is.True);
    }
}
