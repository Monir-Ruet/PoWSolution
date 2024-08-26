using Authentication.Configuration;
using Authentication.Models.DapperIdentity;

namespace Authentication.Helper;

public interface IJwtTokenGenerator
{
    string GenerateJwtToken(ApplicationUser user);
}