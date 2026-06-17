using Microsoft.AspNetCore.Identity;

namespace SecureFileHandler_Amein.Data
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {
        public byte[]? Salt { get; set; }
    }

}
