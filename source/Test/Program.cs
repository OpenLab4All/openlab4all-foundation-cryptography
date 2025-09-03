using System;
using System.Linq;
using System.Text;
using OpenLab4All.Foundation.Cryptography;

namespace Test
{
  internal class Program
  {
    static void Main(string[] args)
    {
      Console.OutputEncoding = Encoding.UTF8;

      Test_CryptoRandom();
      Test_Bytes_and_Base64Url();
      Test_Hash_and_Hmac();
      Test_Kdf();
      Test_ConstantTime();
      Test_CryptoBox();
      Test_SecretManager();

      Console.WriteLine("\n=== All tests executed. ===");
    }

    static void Title(string t)
    {
      Console.WriteLine();
      Console.WriteLine("============================================");
      Console.WriteLine(t);
      Console.WriteLine("============================================");
    }

    static void Test_CryptoRandom()
    {
      Title("CryptoRandom: GetBytes & GetToken");

      var r16 = CryptoRandom.GetBytes(16);
      Console.WriteLine("Random 16 bytes (hex): " + Bytes.ToHex(r16));

      var tokenAlphaNum = CryptoRandom.GetToken(16); // default alphabet
      Console.WriteLine("Random alphanumeric token (16): " + tokenAlphaNum);

      var customAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no ambiguous chars
      var tokenCustom = CryptoRandom.GetToken(20, customAlphabet);
      Console.WriteLine("Random custom token (20): " + tokenCustom);
    }

    static void Test_Bytes_and_Base64Url()
    {
      Title("Bytes & Base64Url");

      var text = "Hello Perú!";
      var bytes = Bytes.FromUtf8(text);
      Console.WriteLine("Original text: " + text);
      Console.WriteLine("UTF8 length: " + bytes.Length);

      var hex = Bytes.ToHex(bytes);
      Console.WriteLine("Hex: " + hex);
      var backFromHex = Bytes.FromHex(hex);
      Console.WriteLine("Hex -> Text: " + Bytes.ToUtf8(backFromHex));

      var b64 = Bytes.ToBase64(bytes); // Standard Base64
      Console.WriteLine("Base64: " + b64);
      var b64Back = Bytes.FromBase64(b64);
      Console.WriteLine("Base64 -> Text: " + Bytes.ToUtf8(b64Back));

      var b64url = Base64Url.ToBase64Url(bytes); // Base64Url
      Console.WriteLine("Base64Url: " + b64url);
      var b64urlBack = Base64Url.FromBase64Url(b64url);
      Console.WriteLine("Base64Url -> Text: " + Bytes.ToUtf8(b64urlBack));

      // Shortcuts Encode/Decode (string <-> string)
      var b64urlEncoded = Base64Url.Encode(text);
      var decodedText = Base64Url.Decode(b64urlEncoded);
      Console.WriteLine("Base64Url.Encode/Decode: " + decodedText);
    }

    static void Test_Hash_and_Hmac()
    {
      Title("Hash & Hmac");

      var payload = Bytes.FromUtf8("message to hash");
      var sha256 = Hash.Sha256(payload);
      var sha512 = Hash.Sha512(payload);
      Console.WriteLine("SHA-256: " + Bytes.ToHex(sha256));
      Console.WriteLine("SHA-512: " + Bytes.ToHex(sha512));

      var hmacKey = CryptoRandom.GetBytes(32);
      var hmac256 = Hmac.Sha256(hmacKey, payload);
      var hmac512 = Hmac.Sha512(hmacKey, payload);
      Console.WriteLine("HMAC-SHA256: " + Bytes.ToHex(hmac256));
      Console.WriteLine("HMAC-SHA512: " + Bytes.ToHex(hmac512));
    }

    static void Test_Kdf()
    {
      Title("Kdf (PBKDF2)");

      var password = Bytes.FromUtf8("StrongPassw0rd!");
      var salt = CryptoRandom.GetBytes(16);
      var derived = Kdf.Pbkdf2(password, salt, iterations: 100_000, outputBytes: 64);

      Console.WriteLine("Salt (hex):    " + Bytes.ToHex(salt));
      Console.WriteLine("Derived (hex): " + Bytes.ToHex(derived));
      Console.WriteLine("encKey (hex):  " + Bytes.ToHex(derived.Take(32).ToArray()));
      Console.WriteLine("macKey (hex):  " + Bytes.ToHex(derived.Skip(32).Take(32).ToArray()));
    }

    static void Test_ConstantTime()
    {
      Title("ConstantTime.FixedTimeEquals");

      var a = Bytes.FromUtf8("abcdef");
      var b = Bytes.FromUtf8("abcdef");
      var c = Bytes.FromUtf8("abcdeg");

      Console.WriteLine("a vs b (equal):   " + ConstantTime.FixedTimeEquals(a, b)); // True
      Console.WriteLine("a vs c (differs): " + ConstantTime.FixedTimeEquals(a, c)); // False
    }

    static void Test_CryptoBox()
    {
      Title("CryptoBox (Encrypt-then-MAC)");

      var encKey = CryptoRandom.GetBytes(32);
      var macKey = CryptoRandom.GetBytes(32);

      var secret = "my super secret token";
      var blob = CryptoBox.Encrypt(Bytes.FromUtf8(secret), encKey, macKey);
      var token = Base64Url.ToBase64Url(blob);

      Console.WriteLine("Token (Base64Url): " + token);

      var blob2 = Base64Url.FromBase64Url(token);
      var plain = CryptoBox.Decrypt(blob2, encKey, macKey);

      Console.WriteLine("Recovered: " + Bytes.ToUtf8(plain));
    }

    // ---------- SecretManager (KEK + purpose) ----------
    static void Test_SecretManager()
    {
      Title("SecretManager (master key + purpose)");

      // Master key (KEK): in real scenarios load it securely (DPAPI, KeyVault, env var)
      var masterKey = CryptoRandom.GetBytes(64);

      // Example 1: DB password
      var purposeDb = "DbPassword";
      var dbPasswordPlain = "P@ssw0rd-DB!";
      var dbToken = SecretManager.EncryptToToken(dbPasswordPlain, masterKey, purposeDb);
      Console.WriteLine("DB token: " + dbToken);
      var dbRecovered = SecretManager.DecryptFromToken(dbToken, masterKey, purposeDb);
      Console.WriteLine("DB recovered: " + dbRecovered);

      // Example 2: Stripe API key (different purpose => different derived keys)
      var purposeStripe = "StripeApiKey";
      var stripePlain = "sk_live_123456789";
      var stripeToken = SecretManager.EncryptToToken(stripePlain, masterKey, purposeStripe);
      Console.WriteLine("Stripe token: " + stripeToken);
      var stripeRecovered = SecretManager.DecryptFromToken(stripeToken, masterKey, purposeStripe);
      Console.WriteLine("Stripe recovered: " + stripeRecovered);

      // Versioned token example (key rotation friendly)
      var versioned = SecretManager.EncryptToVersionedToken("k1", "smtp-secret", masterKey, "SmtpPassword");
      Console.WriteLine("Versioned token: " + versioned);

      var tuple = SecretManager.DecryptFromVersionedToken(
        versioned,
        keyId => masterKey, // resolver demo (for k1 return masterKey)
        "SmtpPassword"
      );
      Console.WriteLine("Versioned recovered (keyId=" + tuple.KeyId + "): " + tuple.Plaintext);
    }
  }
}
