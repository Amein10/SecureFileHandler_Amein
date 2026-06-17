using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace SecureFileHandler_Amein.Data
{
    public partial class FileInfoDbContext : DbContext
    {
        public FileInfoDbContext()
        {
        }

        public FileInfoDbContext(DbContextOptions<FileInfoDbContext> options)
            : base(options)
        {
        }

        public virtual DbSet<RegisteredFile> RegisteredFiles { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
