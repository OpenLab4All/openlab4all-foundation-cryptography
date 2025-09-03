using System;
using System.Security.Cryptography;

namespace OpenLab4All.Foundation.Cryptography
{
  public static class Kdf
  {
    public static byte[] Pbkdf2(byte[] password, byte[] salt, int iterations, int outputBytes)
    {
      using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations))
      {
        return pbkdf2.GetBytes(outputBytes);
      }
    }
  }
}
