namespace Authentication.Models.DapperIdentity;

internal class UserToken
{
    public required string UserId { get; set; }
    public required string LoginProvider { get; set; }
    public required string Name { get; set; }
    public required string Value { get; set; }
}