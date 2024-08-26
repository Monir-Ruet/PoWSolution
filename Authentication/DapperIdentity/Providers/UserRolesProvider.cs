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
         
                 SELECT r.Id AS RoleId, r.Name AS RoleName
                 FROM [{_databaseConnectionFactory.DbSchema}].[Roles] AS r
                 INNER JOIN [{_databaseConnectionFactory.DbSchema}].[UserRoles] AS ur ON ur.RoleId = r.Id
                 WHERE ur.UserId = @UserId
                 
         """;

        await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
        return await sqlConnection.QueryAsync<UserRole>(command, new {
            UserId = user.Id
        });
    }
}