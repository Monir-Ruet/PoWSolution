namespace Authentication.Models.DapperIdentity;

internal class RoleClaim
{
    public required string Id { get; set; }
    public required string RoleId { get; set; }
    public required string ClaimType { get; set; }
    public required string ClaimValue { get; set; }
}