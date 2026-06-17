namespace SecureFileHandler_Amein.Codes
{
    public class UploadPayload_AES_GCM
    {
        public string FileName { get; set; } = "";
        public string FileExtension { get; set; } = "";
        public byte[] Encrypted_AES_Key { get; set; } = new byte[0];
        public byte[] Nonce { get; set; } = new byte[0];
        public byte[] Tag { get; set; } = new byte[0];
        public byte[] Ciphertext { get; set; } = new byte[0];
    }
}
