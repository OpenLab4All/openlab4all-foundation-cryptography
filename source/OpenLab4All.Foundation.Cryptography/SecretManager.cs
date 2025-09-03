using System;
using System.Linq;
using System.Text;

namespace OpenLab4All.Foundation.Cryptography
{
  public static class SecretManager
  {
    public const int DerivedLengthBytes = 64;   // 32 (enc) + 32 (mac)
    public const int Pbkdf2Iterations = 100_000;
    public const string SaltPrefix = "SecretManager|";

    public static string EncryptToToken(string plaintext, byte[] masterKey, string purpose)
    {
      if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
      var plaintextBytes = Bytes.FromUtf8(plaintext);
      var blob = EncryptToBlob(plaintextBytes, masterKey, purpose);
      return Base64Url.ToBase64Url(blob);
    }

    public static string DecryptFromToken(string token, byte[] masterKey, string purpose)
    {
      if (string.IsNullOrWhiteSpace(token)) throw new ArgumentNullException(nameof(token));
      var blob = Base64Url.FromBase64Url(token);
      var bytes = DecryptFromBlob(blob, masterKey, purpose);
      return Bytes.ToUtf8(bytes);
    }

    public static byte[] EncryptToBlob(byte[] plaintext, byte[] masterKey, string purpose)
    {
      if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
      DeriveKeys(masterKey, purpose, out var encKey, out var macKey);
      return CryptoBox.Encrypt(plaintext, encKey, macKey);
    }

    public static byte[] DecryptFromBlob(byte[] blob, byte[] masterKey, string purpose)
    {
      if (blob == null) throw new ArgumentNullException(nameof(blob));
      DeriveKeys(masterKey, purpose, out var encKey, out var macKey);
      return CryptoBox.Decrypt(blob, encKey, macKey);
    }

    public static string EncryptToVersionedToken(string keyId, string plaintext, byte[] masterKey, string purpose)
    {
      if (string.IsNullOrWhiteSpace(keyId)) throw new ArgumentNullException(nameof(keyId));
      var token = EncryptToToken(plaintext, masterKey, purpose);
      return $"{keyId}.{token}";
    }

    public static (string Plaintext, string KeyId) DecryptFromVersionedToken(string versioned, Func<string, byte[]> masterKeyResolver, string purpose)
    {
      if (string.IsNullOrWhiteSpace(versioned)) throw new ArgumentNullException(nameof(versioned));
      if (masterKeyResolver == null) throw new ArgumentNullException(nameof(masterKeyResolver));

      var idx = versioned.IndexOf('.');
      if (idx <= 0) throw new FormatException("Invalid versioned token format. Expected 'keyId.base64UrlToken'.");

      var keyId = versioned.Substring(0, idx);
      var token = versioned.Substring(idx + 1);

      var masterKey = masterKeyResolver(keyId) ?? throw new ArgumentException("Resolver returned null master key.", nameof(masterKeyResolver));
      var plain = DecryptFromToken(token, masterKey, purpose);
      return (plain, keyId);
    }

    private static void DeriveKeys(byte[] masterKey, string purpose, out byte[] encKey, out byte[] macKey)
    {
      if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
      if (string.IsNullOrWhiteSpace(purpose)) throw new ArgumentNullException(nameof(purpose));
      if (masterKey.Length < 32) throw new ArgumentException("Master key must be at least 32 bytes.", nameof(masterKey));

      var salt = Encoding.UTF8.GetBytes(SaltPrefix + purpose);
      var derived = Kdf.Pbkdf2(masterKey, salt, Pbkdf2Iterations, DerivedLengthBytes);

      encKey = derived.Take(32).ToArray();
      macKey = derived.Skip(32).Take(32).ToArray();
    }
  }
}
