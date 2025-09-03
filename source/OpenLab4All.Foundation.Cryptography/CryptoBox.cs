using System;
using System.Security.Cryptography;

namespace OpenLab4All.Foundation.Cryptography
{
  public static class CryptoBox
  {
    public const byte Version = 0x01;
    public const int IvLen = AesCbc.IvSize;
    public const int TagLen = 32; // HMAC-SHA256

    public static byte[] Encrypt(byte[] plaintext, byte[] encryptionKey, byte[] macKey)
    {
      if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
      if (encryptionKey == null) throw new ArgumentNullException(nameof(encryptionKey));
      if (macKey == null) throw new ArgumentNullException(nameof(macKey));
      ValidateKey(encryptionKey);
      ValidateKey(macKey);

      var iv = CryptoRandom.GetBytes(IvLen);
      var ct = AesCbc.Encrypt(plaintext, encryptionKey, iv);

      // data to MAC = [version||iv||ct]
      var toMac = Concat(new[] { new[] { Version }, iv, ct });
      var tag = Hmac.Sha256(macKey, toMac);

      return Concat(new[] { new[] { Version }, iv, ct, tag });
    }

    public static byte[] Decrypt(byte[] blob, byte[] encryptionKey, byte[] macKey)
    {
      if (blob == null) throw new ArgumentNullException(nameof(blob));
      if (encryptionKey == null) throw new ArgumentNullException(nameof(encryptionKey));
      if (macKey == null) throw new ArgumentNullException(nameof(macKey));
      ValidateKey(encryptionKey);
      ValidateKey(macKey);

      if (blob.Length < 1 + IvLen + TagLen)
        throw new CryptographicException("Ciphertext too short.");

      var pos = 0;
      var version = blob[pos++];

      if (version != Version) throw new CryptographicException($"Unsupported version: {version}");

      var iv = new byte[IvLen];
      Buffer.BlockCopy(blob, pos, iv, 0, IvLen);
      pos += IvLen;

      var tag = new byte[TagLen];
      Buffer.BlockCopy(blob, blob.Length - TagLen, tag, 0, TagLen);

      var ctLen = blob.Length - pos - TagLen;
      if (ctLen <= 0) throw new CryptographicException("Invalid ciphertext length.");
      var ct = new byte[ctLen];
      Buffer.BlockCopy(blob, pos, ct, 0, ctLen);

      var toMac = Concat(new[] { new[] { version }, iv, ct });
      var expected = Hmac.Sha256(macKey, toMac);
      if (!ConstantTime.FixedTimeEquals(tag, expected))
        throw new CryptographicException("Authentication failed.");

      return AesCbc.Decrypt(ct, encryptionKey, iv);
    }

    private static void ValidateKey(byte[] key)
    {
      if (!(key.Length == 16 || key.Length == 24 || key.Length == 32))
        throw new ArgumentException("Key must be 16, 24, or 32 bytes.", nameof(key));
    }

    private static byte[] Concat(byte[][] parts)
    {
      var total = 0;
      foreach (var p in parts) total += p.Length;
      var res = new byte[total];
      int offset = 0;
      foreach (var p in parts)
      {
        Buffer.BlockCopy(p, 0, res, offset, p.Length);
        offset += p.Length;
      }
      return res;
    }
  }
}
