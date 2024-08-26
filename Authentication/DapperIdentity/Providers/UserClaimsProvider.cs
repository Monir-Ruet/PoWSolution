using System.Security.Claims;
using Authentication.Data;
using Authentication.Models.DapperIdentity;
using Dapper;

namespace Authentication.DapperIdentity.Providers;

internal class UserClaimsProvider
{
    private readonly IDatabaseConnection _databaseConnectionFactory;

    internal UserClaimsProvider(IDatabaseConnection databaseConnectionFactory)
    {
        _databaseConnectionFactory = databaseConnectionFactory;
    }

    public async Task<IList<Claim>> GetClaimsAsync(ApplicationUser user)
    {
        var command =
        $@"
        SELECT *
        FROM [{_databaseConnectionFactory.DbSchema}].[UserClaims]
        WHERE 
            UserId = @UserId
        ";

        await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
        return (
                await sqlConnection.QueryAsync<UserClaim>(command, new { UserId = user.Id })
            )
            .Select(e => new Claim(e.ClaimType, e.ClaimValue))
            .ToList();
    }
}