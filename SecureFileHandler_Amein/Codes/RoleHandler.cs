using Microsoft.AspNetCore.Identity;
using SecureFileHandler_Amein.Data;

namespace SecureFileHandler_Amein.Codes
{
    public class RoleHandler
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleHandler(IServiceProvider serviceProvider, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _serviceProvider = serviceProvider;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<string> CreateUserRoles(string user, string role)
        {
            //var roleManager = _serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userRoleCheck = await _roleManager.RoleExistsAsync(role);
            if (!userRoleCheck)
                await _roleManager.CreateAsync(new IdentityRole(role));

            Data.ApplicationUser identityUser = await _userManager.FindByNameAsync(user);
            await _userManager.AddToRoleAsync(identityUser, role);

            return "User added to role.";
        }
    }
}
