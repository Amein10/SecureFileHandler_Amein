using Microsoft.AspNetCore.Components.Forms;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;

namespace SecureFileHandler_Amein.Codes
{
    public class HashingHandler
    {
        private readonly Microsoft.AspNetCore.DataProtection.IDataProtector _protector;

        public HashingHandler(Microsoft.AspNetCore.DataProtection.IDataProtectionProvider provider) =>
            _protector = provider.CreateProtector("AESHandler-AESKey");

        #region SHA

        public dynamic SHAHashing(dynamic valueToHash) =>
            valueToHash is byte[]? SHA256.Create().ComputeHash(valueToHash)
            : Convert.ToHexString(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(valueToHash)));

        #endregion

        #region HMAC

        public byte[] HMACHashing(byte[] valueToHash)
        {
            //  Opret en 256-bit nøgle.
            byte[] key = new byte[32];

            // Gem/hent nøglen.
            if (File.Exists(@"Keys\hmac.key"))
            {
                byte[] protectedKey = File.ReadAllBytes(@"Keys\hmac.key");
                key = _protector.Unprotect(protectedKey);
            }
            else
            {
                RandomNumberGenerator.Fill(key);
                byte[] protectedKey = _protector.Protect(key);
                File.WriteAllBytes(@"Keys\hmac.key", protectedKey);
            }

            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(valueToHash);
        }

        #endregion

        #region PBKDF2

        public dynamic PBKDF2Hashing(dynamic valueToHash) =>
            Rfc2898DeriveBytes.Pbkdf2(valueToHash is byte[]? valueToHash
            : Encoding.UTF8.GetBytes(valueToHash), RandomNumberGenerator.GetBytes(16), 10, HashAlgorithmName.SHA256, 32);

        public dynamic PBKDF2Hashing_WithPepper(dynamic valueToHash, byte[] salt)
        {
            //byte[] salt = Encoding.UTF8.GetBytes("230271");
            //byte[] salt = RandomNumberGenerator.GetBytes(16);

            // Husk at sætte miljøvariablen PEPPER_KEY i dit system (eller hosting miljø) med kommando:
            // setx PEPPER_KEY "min-lange-tilfældige-pepper-værdi" (For at slette igen kør kommando: reg delete "HKCU\Environment" /F /V PEPPER_KEY)
            // Hvis din pepper er null efter at sæt miljøvariablen, genstart Visual Studio.
            // Alternativt kan du sætte miljøvariablen i launchSettings.json for dit projekt under "environmentVariables".
            var pepper = Environment.GetEnvironmentVariable("PEPPER_KEY");
            if (string.IsNullOrEmpty(pepper))
                throw new Exception("Pepper ikke sat i miljøvariabler!");

            var passwordWithPepper = valueToHash + pepper;

            byte[] hashedValueAsByteArray = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(passwordWithPepper),
                salt,
                100_000, // anbefalet iterationer
                HashAlgorithmName.SHA256,
                32
            );

            if (valueToHash is byte[])
                return hashedValueAsByteArray;
            else
                return Convert.ToHexString(hashedValueAsByteArray);
        }

        #endregion

        #region BCrypt

        // Aproach 1
        public string BCryptHashing1(string textToHash) =>
            BCrypt.Net.BCrypt.HashPassword(textToHash);

        public bool BCryptVerifyHashing1(string textToHash, string hashedValue) =>
            BCrypt.Net.BCrypt.Verify(textToHash, hashedValue);


        // Aproach 2
        public string BCryptHashing2(string textToHash) =>
            BCrypt.Net.BCrypt.HashPassword(textToHash, BCrypt.Net.BCrypt.GenerateSalt(10), true, BCrypt.Net.HashType.SHA256);

        public bool BCryptVerifyHashing2(string textToHash, string hashedValue) =>
            BCrypt.Net.BCrypt.Verify(textToHash, hashedValue, true, BCrypt.Net.HashType.SHA256);


        #endregion
    }
}
