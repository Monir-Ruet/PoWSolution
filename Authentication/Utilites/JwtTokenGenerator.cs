using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Authentication.Configuration;
using Authentication.Models.DapperIdentity;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Helper;

public class JwtTokenGenerator(AppConfiguration configuration) :  IJwtTokenGenerator
{
    public string GenerateJwtToken(ApplicationUser user)
    {
        var claims = new[]
        {
            new Claim("Email", user.Email),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
        };
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.AuthSettings.Key));
        
        var token = new JwtSecurityToken(
            issuer: configuration.AuthSettings.Issuer,
            audience: configuration.AuthSettings.Audience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

        var tokenAsString = new JwtSecurityTokenHandler().WriteToken(token);
        return tokenAsString;
    }
}