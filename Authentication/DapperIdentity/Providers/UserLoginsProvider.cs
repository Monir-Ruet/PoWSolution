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
            const string command = 
                $"""
                SELECT
                    U.Id,
                    U.UserName,
                    U.Email,
                    U.PhoneNumber,
                    U.Picture
                FROM Users U
                INNER JOIN UserLogins UL
                ON U.Id = UL.UserId
                WHERE 
                    UL.LoginProvider = @LoginProvider 
                AND UL.ProviderKey = @ProviderKey
                """;

            await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
            var user = await sqlConnection.QuerySingleOrDefaultAsync<ApplicationUser?>(command, new {
                LoginProvider = loginProvider,
                ProviderKey = providerKey
            });

            return user;
        }
    }