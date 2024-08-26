namespace Authentication.Models.DapperIdentity;

internal class UserClaim
{
    public required string Id { get; set; }
    public required string UserId { get; set; }
    public required string ClaimType { get; set; }
    public required string ClaimValue { get; set; }
}