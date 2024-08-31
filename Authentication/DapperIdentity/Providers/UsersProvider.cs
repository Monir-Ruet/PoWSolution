using System.Security.Claims;
using Authentication.Data;
using Authentication.Models.DapperIdentity;
using Dapper;
using Microsoft.AspNetCore.Identity;

namespace Authentication.DapperIdentity.Providers;

internal class UsersProvider
    {
        private readonly IDatabaseConnection _databaseConnectionFactory;

        internal UsersProvider(IDatabaseConnection databaseConnectionFactory)
        {
            _databaseConnectionFactory = databaseConnectionFactory;
        }

        public async Task<IdentityResult> CreateAsync(ApplicationUser user) {
            var command = 
            $@"
            INSERT INTO [{_databaseConnectionFactory.DbSchema}].[Users]
            VALUES (@Id, @UserName, @NormalizedUserName, @Email, @Picture, @NormalizedEmail, @EmailConfirmed, @PasswordHash, @SecurityStamp, @ConcurrencyStamp,
                    @PhoneNumber, @PhoneNumberConfirmed, @TwoFactorEnabled, @LockoutEnd, @LockoutEnabled, @AccessFailedCount)
            ";

            int rowsInserted;

            await using (var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync()) {
                rowsInserted = await sqlConnection.ExecuteAsync(command, new {
                    user.Id,
                    user.UserName,
                    user.NormalizedUserName,
                    user.Email,
                    user.Picture,
                    user.NormalizedEmail,
                    user.EmailConfirmed,
                    user.PasswordHash,
                    user.SecurityStamp,
                    user.ConcurrencyStamp,
                    user.PhoneNumber,
                    user.PhoneNumberConfirmed,
                    user.TwoFactorEnabled,
                    user.LockoutEnd,
                    user.LockoutEnabled,
                    user.AccessFailedCount
                });
            }

            return rowsInserted == 1 ? IdentityResult.Success : IdentityResult.Failed(new IdentityError 
            {
                Code = nameof(CreateAsync),
                Description = $"User with email {user.Email} could not be inserted."
            });
        }

        public async Task<IdentityResult> DeleteAsync(ApplicationUser user) {
            var command = 
            $@"
            DELETE FROM [{_databaseConnectionFactory.DbSchema}].[Users]
            WHERE 
                Id = @Id
            ";

            int rowsDeleted;

            await using (var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync()) {
                rowsDeleted = await sqlConnection.ExecuteAsync(command, new {
                    user.Id
                });
            }

            return rowsDeleted == 1 ? IdentityResult.Success : IdentityResult.Failed(new IdentityError {
                Code = nameof(DeleteAsync),
                Description = $"User with email {user.Email} could not be deleted."
            });
        }

        public async Task<ApplicationUser?> FindByIdAsync(Guid userId) {
            var command = 
            $@"
            SELECT
                Id,
                UserName,
                Email,
                PhoneNumber,
                Picture
            FROM [{_databaseConnectionFactory.DbSchema}].[Users]
            WHERE 
                Id = @Id
            ";

            await using (var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync())
            {
                return await sqlConnection.QuerySingleOrDefaultAsync<ApplicationUser?>(command, new
                {
                    Id = userId
                });
            };
        }

        public async Task<ApplicationUser?> FindByNameAsync(string normalizedUserName) {
            var command = 
            $@"
            SELECT 
                Id,
                UserName,
                Email,
                PhoneNumber,
                Picture
            FROM [{_databaseConnectionFactory.DbSchema}].[Users]
            WHERE 
                NormalizedUserName = @NormalizedUserName
            ";

            await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
            return await sqlConnection.QuerySingleOrDefaultAsync<ApplicationUser?>(command, new 
            {
                NormalizedUserName = normalizedUserName
            });
        }

        public async Task<ApplicationUser?> FindByEmailAsync(string normalizedEmail) {
            var command = 
            $@"
            SELECT
                Id,
                UserName,
                Email,
                PhoneNumber,
                Picture
            FROM [{_databaseConnectionFactory.DbSchema}].[Users]
            WHERE 
                NormalizedEmail = @NormalizedEmail
            ";

            await using (var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync())
            {
                return await sqlConnection.QuerySingleOrDefaultAsync<ApplicationUser?>(command, new
                {
                    NormalizedEmail = normalizedEmail
                });
            };
        }

        public async Task<IdentityResult> UpdateAsync(ApplicationUser user) {
             var updateUserCommand =
            $@"
            UPDATE [{_databaseConnectionFactory.DbSchema}].[Users]
            SET 
                UserName = @UserName,
                NormalizedUserName = @NormalizedUserName,
                Email = @Email,
                Picture = @Picture,
                NormalizedEmail = @NormalizedEmail,
                EmailConfirmed = @EmailConfirmed,
                PasswordHash = @PasswordHash, 
                SecurityStamp = @SecurityStamp, 
                ConcurrencyStamp = @ConcurrencyStamp, 
                PhoneNumber = @PhoneNumber,
                PhoneNumberConfirmed = @PhoneNumberConfirmed, 
                TwoFactorEnabled = @TwoFactorEnabled, 
                LockoutEnd = @LockoutEnd, 
                LockoutEnabled = @LockoutEnabled,
                AccessFailedCount = @AccessFailedCount
            WHERE 
                Id = @Id
            ";

            await using (var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync())
            {
                await using var transaction = await sqlConnection.BeginTransactionAsync();
                await sqlConnection.ExecuteAsync(updateUserCommand, new 
                {
                    user.UserName,
                    user.NormalizedUserName,
                    user.Email,
                    user.Picture,
                    user.NormalizedEmail,
                    user.EmailConfirmed,
                    user.PasswordHash,
                    user.SecurityStamp,
                    user.ConcurrencyStamp,
                    user.PhoneNumber,
                    user.PhoneNumberConfirmed,
                    user.TwoFactorEnabled,
                    user.LockoutEnd,
                    user.LockoutEnabled,
                    user.AccessFailedCount,
                    user.Id
                }, transaction);

                if (user?.Claims?.Count > 0) {
                    var deleteClaimsCommand = 
                    $@"
                    DELETE
                    FROM [{_databaseConnectionFactory.DbSchema}].[UserClaims]
                    WHERE 
                        UserId = @UserId
                    ";

                    await sqlConnection.ExecuteAsync(deleteClaimsCommand, new {
                        UserId = user.Id
                    }, transaction);
    
                    var insertClaimsCommand = 
                    $@"
                    INSERT INTO [{_databaseConnectionFactory.DbSchema}].[UserClaims] 
                        (UserId, ClaimType, ClaimValue)
                    VALUES 
                        (@UserId, @ClaimType, @ClaimValue)
                    ";

                    await sqlConnection.ExecuteAsync(insertClaimsCommand, user.Claims.Select(x => new 
                    {
                        UserId = user.Id,
                        ClaimType = x.Type,
                        ClaimValue = x.Value
                    }), transaction);
                }

                if (user?.Logins?.Count > 0) {
                    var deleteLoginsCommand = 
                    $@"
                    DELETE
                    FROM [{_databaseConnectionFactory.DbSchema}].[UserLogins]
                    WHERE 
                        UserId = @UserId
                    ";

                    await sqlConnection.ExecuteAsync(deleteLoginsCommand, new {
                        UserId = user.Id
                    }, transaction);

                    var insertLoginsCommand = 
                    $@"
                    INSERT INTO [{_databaseConnectionFactory.DbSchema}].[UserLogins] 
                        (LoginProvider, ProviderKey, ProviderDisplayName, UserId)
                    VALUES 
                        (@LoginProvider, @ProviderKey, @ProviderDisplayName, @UserId)
                    ";

                    await sqlConnection.ExecuteAsync(insertLoginsCommand, user.Logins.Select(x => new 
                    {
                        x.LoginProvider,
                        x.ProviderKey,
                        x.ProviderDisplayName,
                        UserId = user.Id
                    }), transaction);
                }

                if (user.Roles?.Count > 0) {
                    var deleteRolesCommand = 
                    $@"
                    DELETE
                    FROM [{_databaseConnectionFactory.DbSchema}].[UserRoles]
                    WHERE 
                        UserId = @UserId
                    ";

                    await sqlConnection.ExecuteAsync(deleteRolesCommand, new {
                        UserId = user.Id
                    }, transaction);

                    var insertRolesCommand = 
                    $@"
                    INSERT INTO [{_databaseConnectionFactory.DbSchema}].[UserRoles] 
                        (UserId, RoleId)
                    VALUES 
                        (@UserId, @RoleId)
                    ";

                    await sqlConnection.ExecuteAsync(insertRolesCommand, user.Roles.Select(x => new 
                    {
                        UserId = user.Id,
                        x.RoleId
                    }), transaction);
                }

                if (user?.Tokens?.Count > 0) {
                    var deleteTokensCommand = 
                    $@"
                    DELETE
                    FROM [{_databaseConnectionFactory.DbSchema}].[UserTokens]
                    WHERE 
                        UserId = @UserId
                    ";

                    await sqlConnection.ExecuteAsync(deleteTokensCommand, new 
                    {
                        UserId = user.Id
                    }, transaction);

                    var insertTokensCommand = 
                    $@"
                    INSERT INTO [{_databaseConnectionFactory.DbSchema}].[UserTokens] 
                        (UserId, LoginProvider, Name, Value)
                    VALUES 
                        (@UserId, @LoginProvider, @Name, @Value)
                    ";

                    await sqlConnection.ExecuteAsync(insertTokensCommand, user.Tokens.Select(x => new 
                    {
                        x.UserId,
                        x.LoginProvider,
                        x.Name,
                        x.Value
                    }), transaction);
                }

                try {
                    await transaction.CommitAsync();
                } catch {
                    try {
                        await transaction.RollbackAsync();
                    } catch {
                        return IdentityResult.Failed(new IdentityError 
                        {
                            Code = nameof(UpdateAsync),
                            Description = $"User with email {user.Email} could not be updated. Operation could not be rolled back."
                        });
                    }

                    return IdentityResult.Failed(new IdentityError 
                    {
                        Code = nameof(UpdateAsync),
                        Description = $"User with email {user.Email} could not be updated. Operation was rolled back."
                    });
                }
            }

            return IdentityResult.Success;
        }

        public async Task<IList<ApplicationUser>> GetUsersInRoleAsync(string roleName) {
            var command = 
            $@"
            SELECT
                U.Id,
                U.UserName,
                U.Email,
                U.PhoneNumber
                U.Picture
            FROM [{_databaseConnectionFactory.DbSchema}].[Users] AS U
            INNER JOIN [{_databaseConnectionFactory.DbSchema}].[UserRoles] AS UR 
            ON U.Id = UR.UserId
            INNER JOIN [{_databaseConnectionFactory.DbSchema}].[Roles] AS R 
            ON UR.RoleId = R.Id
            WHERE 
                R.Name = @RoleName
            ";

            await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
            return (await sqlConnection.QueryAsync<ApplicationUser>(command, new 
            {
                RoleName = roleName
            })).ToList();
        }

        public async Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim) {
            var command = 
            $@"
            SELECT
                U.Id,
                U.UserName,
                U.Email,
                U.PhoneNumber
                U.Picture
            FROM [{_databaseConnectionFactory.DbSchema}].[Users] AS U
            INNER JOIN [{_databaseConnectionFactory.DbSchema}].[UserClaims] AS UC 
            ON U.Id = UC.UserId
            WHERE 
                UC.ClaimType = @ClaimType 
            AND UC.ClaimValue = @ClaimValue
            ";

            await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
            return (await sqlConnection.QueryAsync<ApplicationUser>(command, new 
            {
                ClaimType = claim.Type,
                ClaimValue = claim.Value
            })).ToList();
        }

        public async Task<IEnumerable<ApplicationUser>> GetAllUsers() {
            var command = 
            $@"
            SELECT
                Id,
                UserName,
                Email,
                PhoneNumber,
                Picture
            FROM [{_databaseConnectionFactory.DbSchema}].[Users]
            ";

            await using var sqlConnection = await _databaseConnectionFactory.CreateConnectionAsync();
            return await sqlConnection.QueryAsync<ApplicationUser>(command);
        }
    }