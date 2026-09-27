using Odin.Core;

namespace Odin.Oidc.Login.YouAuth;

/// <summary>
/// Opens a token response field with the cipher the identity says sealed it. The switch is a copy
/// of odin-core's <c>YouAuthCiphers.Open</c> over the same primitives (the identity's own code).
/// Both use the 16-byte exchange secret as the AES-128 key. <c>aes-gcm</c>: a 16-byte IV whose first
/// 12 bytes are the nonce, the 16-byte tag appended to the ciphertext. <c>aes-cbc</c>, or nothing:
/// PKCS#7 padded, unauthenticated, what clients got before the choice existed.
/// </summary>
public static class YouAuthCipher
{
    public static byte[] Open(string? cipher, byte[] cipherText, SensitiveByteArray key, byte[] iv)
    {
        throw new NotImplementedException();
    }
}
