using System;
using System.IO;
using System.Security.Cryptography;

namespace OpenLab4All.Foundation.Cryptography
{
  internal static class AesCbc
  {
    public const int IvSize = 16; // 128-bit block

    public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] iv)
    {
      if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
      if (key == null) throw new ArgumentNullException(nameof(key));
      if (iv == null || iv.Length != IvSize) throw new ArgumentException("Invalid IV length.", nameof(iv));

      using (var aes = Aes.Create())
      {
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;
        using (var encryptor = aes.CreateEncryptor())
        using (var ms = new MemoryStream())
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
          cs.Write(plaintext, 0, plaintext.Length);
          cs.FlushFinalBlock();
          return ms.ToArray();
        }
      }
    }

    public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
    {
      if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
      if (key == null) throw new ArgumentNullException(nameof(key));
      if (iv == null || iv.Length != IvSize) throw new ArgumentException("Invalid IV length.", nameof(iv));

      using (var aes = Aes.Create())
      {
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;
        using (var decryptor = aes.CreateDecryptor())
        using (var msIn = new MemoryStream(ciphertext))
        using (var cs = new CryptoStream(msIn, decryptor, CryptoStreamMode.Read))
        using (var msOut = new MemoryStream())
        {
          cs.CopyTo(msOut);
          return msOut.ToArray();
        }
      }
    }
  }
}
