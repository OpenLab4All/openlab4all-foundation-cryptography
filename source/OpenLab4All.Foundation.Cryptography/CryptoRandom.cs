using System;
using System.Security.Cryptography;
using System.Text;

namespace OpenLab4All.Foundation.Cryptography
{
  public static class CryptoRandom
  {
    public static byte[] GetBytes(int length)
    {
      if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
      var bytes = new byte[length];
      using (var rng = RandomNumberGenerator.Create())
      {
        rng.GetBytes(bytes);
      }
      return bytes;
    }

    public static string GetToken(int length, string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    {
      if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
      if (string.IsNullOrEmpty(alphabet)) throw new ArgumentNullException(nameof(alphabet));

      var buffer = CryptoRandom.GetBytes(length);
      var sb = new StringBuilder(length);

      foreach (var b in buffer)
      {
        sb.Append(alphabet[b % alphabet.Length]);
      }

      return sb.ToString();
    }
  }
}
