using System.Security.Claims;
using Authentication.DapperIdentity.Providers;
using Authentication.Data;
using Authentication.Models.DapperIdentity;
using Microsoft.AspNetCore.Identity;

namespace Authentication.DapperIdentity.Stores;

public sealed class RoleStore(IDatabaseConnection databaseConnectionFactory) : IQueryableRoleStore<ApplicationRole>,
    IRoleClaimStore<ApplicationRole>
{
        private readonly RolesProvider _rolesTable = new(databaseConnectionFactory);
        private readonly RoleClaimsProvider _roleClaimsTable = new(databaseConnectionFactory);


        #region IQueryableRoleStore Implementation
        public IQueryable<ApplicationRole> Roles => Task.Run(() => _rolesTable.GetAllRolesAsync()).Result.AsQueryable();
        #endregion

        #region IRoleStore<ApplicationRole> Implementation
        public Task<IdentityResult> CreateAsync(ApplicationRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            return _rolesTable.CreateAsync(role, cancellationToken);
        }

        public Task<IdentityResult> UpdateAsync(ApplicationRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            return _rolesTable.UpdateAsync(role);
        }

        public Task<IdentityResult> DeleteAsync(ApplicationRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            return _rolesTable.DeleteAsync(role);
        }

        public Task<string> GetRoleIdAsync(ApplicationRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            return Task.FromResult(role.Id);
        }

        public Task<string?> GetRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            return Task.FromResult(role.Name);
        }

        public Task SetRoleNameAsync(ApplicationRole role, string? roleName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            ArgumentNullException.ThrowIfNull(roleName, nameof(roleName));
            role.Name = roleName;
            return Task.CompletedTask;
        }

        public Task<string?> GetNormalizedRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            return Task.FromResult(role.NormalizedName);
        }

        public Task SetNormalizedRoleNameAsync(ApplicationRole role, string? normalizedName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            ArgumentNullException.ThrowIfNull(normalizedName, nameof(normalizedName));
            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        public Task<ApplicationRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(roleId, nameof(roleId));
            var isValidGuid = Guid.TryParse(roleId, out var roleGuid);

            if (!isValidGuid) {
                throw new ArgumentException("Parameter roleId is not a valid Guid.", nameof(roleId));
            }

            return _rolesTable.FindByIdAsync(roleGuid);
        }

        public Task<ApplicationRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(normalizedRoleName, nameof(normalizedRoleName));
            return _rolesTable.FindByNameAsync(normalizedRoleName);
        }

    
        #endregion

        #region IRoleClaimStore<ApplicationRole> Implementation
        public async Task<IList<Claim>> GetClaimsAsync(ApplicationRole role, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            role.Claims = role.Claims ?? (await _roleClaimsTable.GetClaimsAsync(role.Id)).ToList();
            return role.Claims;
        }

        public async Task AddClaimAsync(ApplicationRole role, Claim claim, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            ArgumentNullException.ThrowIfNull(claim, nameof(claim));
            role.Claims = role.Claims ?? (await _roleClaimsTable.GetClaimsAsync(role.Id)).ToList();
            var foundClaim = role.Claims.FirstOrDefault(x => x.Type == claim.Type);

            if (foundClaim != null) {
                role.Claims.Remove(foundClaim);
                role.Claims.Add(claim);
            } else {
                role.Claims.Add(claim);
            }
        }

        public async Task RemoveClaimAsync(ApplicationRole role, Claim claim, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(role, nameof(role));
            ArgumentNullException.ThrowIfNull(claim, nameof(claim));
            role.Claims = role.Claims ?? (await _roleClaimsTable.GetClaimsAsync(role.Id)).ToList();
            role.Claims.Remove(claim);
        }
        #endregion

        private void ReleaseUnmanagedResources()
        {
            // release unmanaged resources here
        }

        private void Dispose(bool disposing)
        {
            ReleaseUnmanagedResources();
            if (disposing)
            {
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~RoleStore()
        {
            Dispose(false);
        }
    }