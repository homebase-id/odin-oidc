using System.Security.Cryptography;
using Odin.Core;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// The wire layout of a token field sealed with aes-gcm, pinned by a vector odin-core's
/// AesGcm.Encrypt produced (odin-core PR #1819): 16-byte key, 16-byte IV whose first 12 bytes are
/// the nonce, tag appended. The app opens it with the same helper; if the helper's layout drifts
/// from what deployed identities send, this is what says so.
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
        var plain = AesGcm.Decrypt(CipherText, Key.ToSensitiveByteArray(), Iv);
        Assert.That(plain.ToStringFromUtf8Bytes(), Is.EqualTo(Plain));
    }

    [Test]
    public void RefusesAChangedByteInsteadOfYieldingGarbage()
    {
        var tampered = (byte[])CipherText.Clone();
        tampered[3] ^= 0x01;
        Assert.That(() => AesGcm.Decrypt(tampered, Key.ToSensitiveByteArray(), Iv), Throws.InstanceOf<CryptographicException>());
    }
}
