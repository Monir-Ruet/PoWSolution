using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace Authentication.Models.DapperIdentity;

public class ApplicationUser : IdentityUser
{
    internal List<Claim>? Claims { get; set; }
    internal List<UserRole>? Roles { get; set; }
    internal List<UserLoginInfo>? Logins { get; set; }
    internal List<UserToken>? Tokens { get; set; }
}