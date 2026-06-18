using System.Security.Cryptography;

namespace SecureFileHandler_Amein.Codes
{
    public class RsaHandler
    {
        private readonly Microsoft.AspNetCore.DataProtection.IDataProtector _protector;
        private string rsa_private_Key_Path = @"Keys\rsa_private.key";
        private string rsa_public_Key_Path = @"Keys\rsa_public.key";

        public RsaHandler(Microsoft.AspNetCore.DataProtection.IDataProtectionProvider provider)
        {
            // C:\Users\no\AppData\Local\ASP.NET\DataProtection-Keys
            // Teksten "AESHandler-AESKey" er en så kaldt: purpose string, et navn som bruges til
            // at identificere og adskille de forskellige beskyttelsesoperationer i data
            // beskyttelsessystemet. Det er vigtigt at bruge unikke purpose strings for forskellige
            // typer data, så de ikke kan forveksles eller misbruges på tværs af forskellige beskyttelsesoperationer.
            _protector = provider.CreateProtector("AES_protected_data");

            using (RSA rsa = RSA.Create(2048))
            {
                if (!File.Exists(rsa_public_Key_Path))
                {
                    byte[] rsa_public_Key = rsa.ExportSubjectPublicKeyInfo();
                    byte[] rsa_private_Key = rsa.ExportRSAPrivateKey();

                    File.WriteAllBytes(rsa_public_Key_Path, _protector.Protect(rsa_public_Key));
                    File.WriteAllBytes(rsa_private_Key_Path, _protector.Protect(rsa_private_Key));
                }
            }
        }

        public byte[] Rsa_public_Key_Path => _protector.Unprotect(File.ReadAllBytes(rsa_public_Key_Path));
        private byte[] Rsa_Private_Key => _protector.Unprotect(File.ReadAllBytes(rsa_private_Key_Path));

        public byte[] Decrypt(byte[] ciphertext)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(Rsa_Private_Key, out _);

            return rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        }

        public byte[] Decrypt_AES_In_GCM_Mode(byte[] encrypted_AES_Key, byte[   ] nonce, byte[] tag, byte[] encryptedData)
        {
            // Decrypt AES key using RSA
            byte[] decrypted_aes_key;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(Rsa_Private_Key, out _);
                decrypted_aes_key = rsa.Decrypt(encrypted_AES_Key, RSAEncryptionPadding.OaepSHA256);
            }

            if (encryptedData.Length < 28)
                throw new ArgumentException("Encrypted data is too short.");
            byte[] ciphertext = new byte[encryptedData.Length - 28];

            Array.Copy(encryptedData, 0, nonce, 0, 12);
            Array.Copy(encryptedData, 12, tag, 0, 16);
            Array.Copy(encryptedData, 28, ciphertext, 0, ciphertext.Length);
            byte[] plainBytes = new byte[ciphertext.Length];

            // Int værdi skal match "tag" størrelse.
            using var aesGcm = new System.Security.Cryptography.AesGcm(decrypted_aes_key, 16);
            aesGcm.Decrypt(nonce, ciphertext, tag, plainBytes);

            return plainBytes;
        }
    }
}