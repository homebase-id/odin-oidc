using System.Security.Cryptography;
using Odin.Core;
using Odin.Core.Cryptography.Crypto;
using Odin.Oidc.Login.YouAuth;
using AesGcm = Odin.Core.Cryptography.Crypto.AesGcm;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// The wire layout of a sealed YouAuth token field, pinned by a vector odin-core's AesGcm.Encrypt
/// produced (odin-core PR #1819): 16-byte key, 16-byte IV whose first 12 bytes are the nonce, tag
/// appended. If this drifts, the broker cannot read what identities send.
/// </summary>
[TestFixture]
public class YouAuthCipherTests
{
    private static readonly byte[] Key = Convert.FromBase64String("AQIDBAUGBwgJCgsMDQ4PEA==");
    private static readonly byte[] Iv = Convert.FromBase64String("oKGio6SlpqeoqaqrrK2urw==");
    private static readonly byte[] CipherText = Convert.FromBase64String(
        "eSH+wgPDdf9DAuxT0Va26ZAeiDUG2FbAy7y5NNKb9cYSjSNtVaVZ8Bt0xQ+4OcspaNt+oIRajgWAfAMQwOZ7PlSx1F6xa6XNrcCYNOn5a72vJWi7zWOhAG9s4Rmi+9Qhmw==");
    private const string Plain = """{"identity":"sam.dotyou.cloud","ss64":"AAECAwQFBgcICQoLDA0ODw==","returnUrl":"/"}""";

    [Test]
    public void OpensWhatTheIdentitySealedWithAesGcm()
    {
        var plain = YouAuthCipher.Open("aes-gcm", CipherText, Key.ToSensitiveByteArray(), Iv);
        Assert.That(plain.ToStringFromUtf8Bytes(), Is.EqualTo(Plain));
    }

    [Test]
    public void RefusesAChangedByteInsteadOfYieldingGarbage()
    {
        var tampered = (byte[])CipherText.Clone();
        tampered[3] ^= 0x01;
        Assert.That(() => YouAuthCipher.Open("aes-gcm", tampered, Key.ToSensitiveByteArray(), Iv), Throws.InstanceOf<CryptographicException>());
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("aes-cbc")]
    public void AbsentOrAesCbcIsWhatClientsGotBefore(string? cipher)
    {
        var key = RandomNumberGenerator.GetBytes(16).ToSensitiveByteArray();
        var plain = RandomNumberGenerator.GetBytes(33);
        var (iv, ct) = AesCbc.Encrypt(plain, key);

        Assert.That(YouAuthCipher.Open(cipher, ct, key, iv), Is.EqualTo(plain));
    }

    [Test]
    public void AesGcmRoundTripsWithTheIdentitysOwnHelper()
    {
        var key = RandomNumberGenerator.GetBytes(16).ToSensitiveByteArray();
        var plain = RandomNumberGenerator.GetBytes(33);
        var (iv, ct) = AesGcm.Encrypt(plain, key);

        Assert.That(YouAuthCipher.Open("aes-gcm", ct, key, iv), Is.EqualTo(plain));
    }

    [Test]
    public void ACipherThisAppDoesNotKnowIsRefused()
    {
        Assert.That(() => YouAuthCipher.Open("rot13", CipherText, Key.ToSensitiveByteArray(), Iv),
            Throws.ArgumentException.With.Message.Contains("rot13"));
    }
}
