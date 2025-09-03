using System;

namespace OpenLab4All.Foundation.Cryptography
{
  public static class ConstantTime
  {
    public static bool FixedTimeEquals(byte[] a, byte[] b)
    {
      if (a == null || b == null) return false;
      if (a.Length != b.Length) return false;
      int diff = 0;
      for (int i = 0; i < a.Length; i++)
        diff |= a[i] ^ b[i];
      return diff == 0;
    }
  }
}
