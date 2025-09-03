using System;
using System.Security.Cryptography;

namespace OpenLab4All.Foundation.Cryptography
{
  public static class Hmac
  {
    public static byte[] Sha256(byte[] key, byte[] data)
    {
      using (var h = new HMACSHA256(key)) return h.ComputeHash(data);
    }

    public static byte[] Sha512(byte[] key, byte[] data)
    {
      using (var h = new HMACSHA512(key)) return h.ComputeHash(data);
    }
  }
}
