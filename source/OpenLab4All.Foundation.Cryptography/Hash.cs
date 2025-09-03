using System;
using System.Security.Cryptography;

namespace OpenLab4All.Foundation.Cryptography
{
  public static class Hash
  {
    public static byte[] Sha256(byte[] data)
    {
      using (var sha = SHA256.Create()) return sha.ComputeHash(data);
    }

    public static byte[] Sha512(byte[] data)
    {
      using (var sha = SHA512.Create()) return sha.ComputeHash(data);
    }
  }
}
