using System.Security.Claims;
using Authentication.Data;
using Authentication.Models.DapperIdentity;
using Dapper;

namespace Authentication.DapperIdentity.Providers;

internal class RoleClaimsProvider
{
    private readonly IDatabaseConnection _databaseConnectionFactory;

    internal RoleClaimsProvider(IDatabaseConnection databaseConnectionFactory)
    {
        _databaseConnectionFactory = databaseConnectionFactory;
    }

    public async Task<IList<Claim>> GetClaimsAsync(string roleId)
    {
        var command = 
        $@"
        SELECT *
        FROM [{_databaseConnectionFactory.DbSchema}].[RoleClaims]
        WHERE 
            RoleId = @RoleId
        ";

        IEnumerable<RoleClaim> roleClaims = new List<RoleClaim>();

        await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
        return (
                await sqlConnection.QueryAsync<RoleClaim>(command, new { RoleId = roleId })
            )
            .Select(x => new Claim(x.ClaimType, x.ClaimValue))
            .ToList();
    }
}