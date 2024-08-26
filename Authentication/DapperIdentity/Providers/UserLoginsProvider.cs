using Authentication.Data;
using Authentication.Models.DapperIdentity;
using Dapper;
using Microsoft.AspNetCore.Identity;

namespace Authentication.DapperIdentity.Providers;

internal class UserLoginsProvider
    {
        private readonly IDatabaseConnection _databaseConnectionFactory;

        internal UserLoginsProvider(IDatabaseConnection databaseConnectionFactory)
        {
            _databaseConnectionFactory = databaseConnectionFactory;
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user) {
            var command = 
            $"""
                         SELECT *
                         FROM [{_databaseConnectionFactory.DbSchema}].[UserLogins]
                         WHERE 
                             UserId = @UserId
             """;

            await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
            return (
                    await sqlConnection.QueryAsync<UserLogin>(command, new { UserId = user.Id })
            )
            .Select(x => new UserLoginInfo(x.LoginProvider, x.ProviderKey, x.ProviderDisplayName))
            .ToList();
        }

        public async Task<ApplicationUser?> FindByLoginAsync(string loginProvider, string providerKey) {
            var command =
                $"""
                 
                             SELECT UserId
                             FROM [{_databaseConnectionFactory.DbSchema}].[UserLogins]
                             WHERE 
                                 LoginProvider = @LoginProvider 
                             AND ProviderKey = @ProviderKey
                             
                 """;

            await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
            var userId = await sqlConnection.QuerySingleOrDefaultAsync<string>(command, new {
                LoginProvider = loginProvider,
                ProviderKey = providerKey
            });

            if (userId == null) {
                return null;
            }

            command = 
                $"""
                             SELECT *
                             FROM [{_databaseConnectionFactory.DbSchema}].[Users]
                             WHERE Id = @Id
                 """;

            var user = await sqlConnection.QuerySingleOrDefaultAsync<ApplicationUser>(command, new { Id = userId });
            return user;
        }
    }