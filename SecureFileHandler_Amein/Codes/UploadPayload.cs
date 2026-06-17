using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SecureFileHandler_Amein.Codes
{
    public class UploadPayload
    {
        public string FileName { get; set; } = "";
        public string FileExtension { get; set; } = "";
        public byte[] Ciphertext { get; set; } = new byte[0];
    }
}
