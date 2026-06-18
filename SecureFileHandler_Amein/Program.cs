using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureFileHandler_Amein.Components;
using SecureFileHandler_Amein.Components.Account;
using SecureFileHandler_Amein.Data;
using Microsoft.AspNetCore.Mvc;
using SecureFileHandler_Amein.Codes;
using static System.Runtime.InteropServices.JavaScript.JSType;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityRedirectManager>();
builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();
builder.Services.AddScoped<RoleHandler>();
builder.Services.AddScoped<HashingHandler>();
builder.Services.AddScoped<RsaHandler>();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
    })
    .AddIdentityCookies();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

var fileUploaderConnectionString = builder.Configuration.GetConnectionString("FileUploaderConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<FileInfoDbContext>(options =>
    options.UseSqlite(fileUploaderConnectionString));

builder.Services.AddIdentityCore<ApplicationUser>(options =>
    {
        options.SignIn.RequireConfirmedAccount = true; // Den skal måske ændres
        options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();

builder.Services.AddHttpClient();

builder.Configuration.GetSection("Kestrel:Endpoints:Https:Url").Value =
    "https://localhost:7000";

builder.Configuration.GetSection("Kestrel:Endpoints:Https:Certificate:Path").Value =
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".aspnet", "https", "Amein.pem");

builder.Configuration.GetSection("Kestrel:Endpoints:Https:Certificate:KeyPath").Value =
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".aspnet", "https", "Amein.key");

// builder.Configuration.GetSection("Kestrel:Endpoints:Https:Certificate:Path").Value = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".aspnet", "https", "Amein.pem");
// builder.Configuration.GetSection("Kestrel:Endpoints:Https:Certificate:KeyPath").Value = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".aspnet", "https", "Amein.key");

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

app.MapGet("/download/{userName}/{fileName}", async (string userName, string fileName, IWebHostEnvironment env, FileInfoDbContext fileInfoDbContext) =>
{
    var filePath = Path.Combine(env.ContentRootPath, "Files", userName, fileName);
    if (!File.Exists(filePath))
        return Results.NotFound();

    var fileBytes = await File.ReadAllBytesAsync(filePath);

    // 2. Slet filens metadata (HMAC fra sender) fra databasen.    
    fileInfoDbContext.RegisteredFiles.Where(f => f.FileName == fileName).ToList().ForEach(f =>
    {
        fileInfoDbContext.RegisteredFiles.Remove(f);
    });
    fileInfoDbContext.SaveChanges();

    // 2. Slet filen fra admin folder.  
    File.Delete(filePath);

    return Results.File(fileBytes, "application/octet-stream", fileName);
});

app.MapPost("/api/handshake", async (HttpRequest request, RsaHandler decryptor) =>
{
    byte[] publicKey = decryptor.Rsa_public_Key_Path;
    return Convert.ToBase64String(publicKey);
});

app.MapPost("/api/upload_encrypted_file", async ([FromBody] UploadPayload payload, RsaHandler decryptor, FileInfoDbContext fileInfoDbContext, HashingHandler hashingHandler, IWebHostEnvironment env) =>
{
    string fileName = payload.FileName;
    string fileExtension = payload.FileExtension;
    byte[] ciphertext = payload.Ciphertext;

    // 1. decrypt to byte[]
    byte[] decrypted_file_as_bytes = decryptor.Decrypt(ciphertext);

    // 2. Gemmer filens metadata i databasen.
    byte[] hashAuth = hashingHandler.HMACHashing(decrypted_file_as_bytes);
    var fileMetaData = new RegisteredFile { FileName = fileName, FileExtension = fileExtension, HashAuth = hashAuth };
    fileInfoDbContext.RegisteredFiles.Where(f => f.FileName == fileName).ToList().ForEach(f =>
    {
        fileInfoDbContext.RegisteredFiles.Remove(f);
    });
    fileInfoDbContext.RegisteredFiles.Add(fileMetaData);
    fileInfoDbContext.SaveChanges();

    // Save file to disk
    var uploadFolder = Path.Combine(env.ContentRootPath, "Files", "admin");
    if (!Directory.Exists(uploadFolder))
        Directory.CreateDirectory(uploadFolder);

    var filePath = Path.Combine(uploadFolder, fileName);
    //string decryptedDataAsString = System.Text.Encoding.UTF8.GetString(decrypted_file_as_bytes);
    await File.WriteAllBytesAsync(filePath, decrypted_file_as_bytes);  // <-- Correct way

    Console.WriteLine($"File saved as {filePath}");

    return Results.Ok(new { path = "/uploads/" + fileName });
});

app.MapPost("/api/upload_aesGcm_encrypted_file", async ([FromBody] UploadPayload_AES_GCM payload, RsaHandler decryptor, FileInfoDbContext fileInfoDbContext, HashingHandler hashingHandler, IWebHostEnvironment env) =>
{
    string fileName = payload.FileName;
    string fileExtension = payload.FileExtension;
    byte[] encrypted_AES_Key = payload.Encrypted_AES_Key;
    byte[] nonce = payload.Nonce;
    byte[] tag = payload.Tag;
    byte[] ciphertext = payload.Ciphertext;

    byte[] decrypted_file_as_bytes = decryptor.Decrypt_AES_In_GCM_Mode(encrypted_AES_Key, nonce, tag, ciphertext);

    // 2. Gemmer filens metadata i databasen.
    byte[] hashAuth = hashingHandler.HMACHashing(decrypted_file_as_bytes);
    var fileMetaData = new RegisteredFile { FileName = fileName, FileExtension = fileExtension, HashAuth = hashAuth };
    fileInfoDbContext.RegisteredFiles.Where(f => f.FileName == fileName).ToList().ForEach(f =>
    {
        fileInfoDbContext.RegisteredFiles.Remove(f);
    });
    fileInfoDbContext.RegisteredFiles.Add(fileMetaData);
    fileInfoDbContext.SaveChanges();

    // Save file to disk
    var uploadFolder = Path.Combine(env.ContentRootPath, "Files", "admin");
    if (!Directory.Exists(uploadFolder))
        Directory.CreateDirectory(uploadFolder);

    var filePath = Path.Combine(uploadFolder, fileName);
    await File.WriteAllBytesAsync(filePath, decrypted_file_as_bytes);

    Console.WriteLine($"File saved as {filePath}");

    return Results.Ok(new { path = "/uploads/" + fileName });
});

app.Run();