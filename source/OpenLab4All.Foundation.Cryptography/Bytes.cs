using System;
using System.Linq;
using System.Text;

namespace OpenLab4All.Foundation.Cryptography
{
  public static class Bytes
  {
    public static byte[] FromHex(string hex)
    {
      if (hex == null) throw new ArgumentNullException(nameof(hex));
      if (hex.Length % 2 != 0) throw new FormatException("Hex string must have even length.");
      var arr = new byte[hex.Length / 2];
      for (int i = 0; i < arr.Length; i++)
      {
        string byteStr = hex.Substring(2 * i, 2);
        arr[i] = Convert.ToByte(byteStr, 16);
      }
      return arr;
    }

    public static string ToHex(byte[] bytes)
    {
      if (bytes == null) throw new ArgumentNullException(nameof(bytes));
      return string.Concat(bytes.Select(b => b.ToString("x2")));
    }

    public static byte[] FromUtf8(string text) => Encoding.UTF8.GetBytes(text ?? throw new ArgumentNullException(nameof(text)));
    public static string ToUtf8(byte[] bytes) => Encoding.UTF8.GetString(bytes ?? throw new ArgumentNullException(nameof(bytes)));

    public static string ToBase64(byte[] bytes) => Convert.ToBase64String(bytes ?? throw new ArgumentNullException(nameof(bytes)));
    public static byte[] FromBase64(string base64) => Convert.FromBase64String(base64 ?? throw new ArgumentNullException(nameof(base64)));
  }
}
