using Authentication.Data;
using Authentication.Models.DapperIdentity;
using Dapper;

namespace Authentication.DapperIdentity.Providers;

internal class UserTokensProvider
{
    private readonly IDatabaseConnection _databaseConnectionFactory;

    internal UserTokensProvider(IDatabaseConnection databaseConnectionFactory)
    {
        _databaseConnectionFactory = databaseConnectionFactory;
    }

    public async Task<IEnumerable<UserToken>> GetTokensAsync(string userId) {
        var command = 
            $"""
             SELECT *
             FROM [{_databaseConnectionFactory.DbSchema}].[AspNetUserTokens]
             WHERE 
                 UserId = @UserId
             """;

        await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
        return await sqlConnection.QueryAsync<UserToken>(command, new {
            UserId = userId
        });
    }
}