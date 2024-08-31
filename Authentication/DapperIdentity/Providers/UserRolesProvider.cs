using Authentication.Data;
using Authentication.Models.DapperIdentity;
using Dapper;

namespace Authentication.DapperIdentity.Providers;

internal class UserRolesProvider
{
    private readonly IDatabaseConnection _databaseConnectionFactory;

    internal UserRolesProvider(IDatabaseConnection databaseConnectionFactory)
    {
        _databaseConnectionFactory = databaseConnectionFactory;
    }

    public async Task<IEnumerable<UserRole>> GetRolesAsync(ApplicationUser user) {
        var command = 
        $"""
         SELECT 
             R.Id AS RoleId, 
             R.Name AS RoleName
         FROM [{_databaseConnectionFactory.DbSchema}].[Roles] AS R
         INNER JOIN [{_databaseConnectionFactory.DbSchema}].[UserRoles] AS UR
         ON UR.RoleId = R.Id
         WHERE 
             UR.UserId = @UserId
         """;

        await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
        return await sqlConnection.QueryAsync<UserRole>(command, new {
            UserId = user.Id
        });
    }
}