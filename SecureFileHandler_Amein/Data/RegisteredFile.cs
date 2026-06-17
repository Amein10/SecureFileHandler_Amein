using System;
using System.Collections.Generic;

namespace SecureFileHandler_Amein.Data
{
    public partial class RegisteredFile
    {
        public int Id { get; set; }

        public string FileName { get; set; } = null!;

        public string FileExtension { get; set; } = null!;

        public byte[] HashAuth { get; set; } = null!;
    }
}
