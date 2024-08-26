namespace Authentication.Models.DapperIdentity;

internal class UserLogin
{
    public required string LoginProvider { get; set; }
    public required string ProviderKey { get; set; }
    public required string ProviderDisplayName { get; set; }
    public required string UserId { get; set; }
}