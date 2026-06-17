// Must install package System.Security.Cryptography.ProtectedData
// Must install package Microsoft.AspNetCore.DataProtection

using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FileTransferApp_Afsender_Amein.Codes;

internal class EncryptionHandler
{
    private readonly Microsoft.AspNetCore.DataProtection.IDataProtector _protector;
    private const string KeyFileName = @"Keys\aes_key.bin";
    private byte[] _key;
    private byte[] _nonce, _tag;

    public EncryptionHandler(Microsoft.AspNetCore.DataProtection.IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("AESHandler-AESKey");
        if (File.Exists(KeyFileName))
        {
            byte[] protectedKey = File.ReadAllBytes(KeyFileName);
            _key = _protector.Unprotect(protectedKey);
        }
        else
        {
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.KeySize = 256;
            _key = aes.Key;

            byte[] protectedKey = _protector.Protect(_key);
            File.WriteAllBytes(KeyFileName, protectedKey);
        }
    }

    public byte[] Nonce => _nonce;
    public byte[] Tag => _tag;

    public byte[] Encrypt(byte[] rsa_public_key, byte[] dataToEncrypt)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(rsa_public_key, out _);

        return rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
    }

    public byte[] Encrypt_File_Content_With_AES_GCM_Mode(byte[] text_To_Encrypt_As_Bytes)
    {
        _nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(12);
        _tag = new byte[16];

        using var aes = new System.Security.Cryptography.AesGcm(_key, 16);
        aes.Encrypt(_nonce, text_To_Encrypt_As_Bytes, text_To_Encrypt_As_Bytes, _tag);

        using var ms = new MemoryStream();
        ms.Write(_nonce, 0, _nonce.Length);
        ms.Write(_tag, 0, _tag.Length);
        ms.Write(text_To_Encrypt_As_Bytes, 0, text_To_Encrypt_As_Bytes.Length);

        return ms.ToArray();
    }

    public byte[] Encrypt_AES_key_with_RSA(byte[] rsa_public_key)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportSubjectPublicKeyInfo(rsa_public_key, out _);
            byte[] encrypted_AES_Key = rsa.Encrypt(_key, RSAEncryptionPadding.OaepSHA256);
            return encrypted_AES_Key;
        }
    }

    public async Task<byte[]> Load_File_Content_To_Memory(IBrowserFile file)
    {
        byte[] file_content_in_memory;
        using (var ms = new MemoryStream())
        {
            await file.OpenReadStream().CopyToAsync(ms);
            file_content_in_memory = ms.ToArray();
        }

        return file_content_in_memory;
    }
}
