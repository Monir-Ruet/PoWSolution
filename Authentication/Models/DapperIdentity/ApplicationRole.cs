using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace Authentication.Models.DapperIdentity;

public class ApplicationRole : IdentityRole
{
    internal List<Claim>? Claims { get; set; }
}