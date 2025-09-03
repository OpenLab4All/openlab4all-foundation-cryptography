using System;
using System.Text;

namespace OpenLab4All.Foundation.Cryptography
{
  public static class Base64Url
  {
    public static string Encode(string text)
      => ToBase64Url(Encoding.UTF8.GetBytes(text));

    public static string Decode(string base64Url)
      => Encoding.UTF8.GetString(FromBase64Url(base64Url));

    public static string ToBase64Url(byte[] bytes)
    {
      var b64 = Convert.ToBase64String(bytes);
      return b64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    public static byte[] FromBase64Url(string base64Url)
    {
      if (base64Url == null) throw new ArgumentNullException(nameof(base64Url));
      string s = base64Url.Replace('-', '+').Replace('_', '/');
      switch (s.Length % 4)
      {
        case 0: break;
        case 2: s += "=="; break;
        case 3: s += "="; break;
        default: throw new FormatException("Invalid Base64Url string length.");
      }
      return Convert.FromBase64String(s);
    }
  }
}
