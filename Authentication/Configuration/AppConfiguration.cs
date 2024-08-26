using System.ComponentModel.DataAnnotations;

namespace Authentication.Configuration;

public class AppConfiguration
{
    public string AllowedOrigins { get; set; } = null!;
    [Required] public string AppName { get; set; } = null!;
    [Required] public string AppUrl { get; set; } = null!;
    [Required] public string ViewUrl { get; set; } = null!;
    [Required] public JwtTokenConfig AuthSettings { get; set; } = null!;
    [Required] public ConnectionStrings ConnectionStrings { get; set; } = null!;
    [Required] public MailConfiguration MailConfiguration { get; set; } = null!;
    [Required] public Authentication Authentication { get; set; } = null!;
}

public class JwtTokenConfig
{
    public string Issuer { get; set; } = null!;
    public string Audience { get; set; } = null!;
    public string Key { get; set; } = null!;

    public int AccessTokenExpiration { get; set; } = 30;
    public int RefreshTokenExpiration { get; set; } = 30;
    public string FrontEndApiKey { get; set; } = null!;
}

public class ConnectionStrings
{
    public string DefaultConnection { get; set; } = null!;
}

public class MailConfiguration
{
    public string Server { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
}

public class Authentication
{
    public OAuthConfig Google { get; set; } = null!;
    public OAuthConfig Github { get; set; } = null!;
    public OAuthConfig Facebook { get; set; } = null!;
}

public class OAuthConfig
{
    public string ClientId { get; set; } = null!;
    public string ClientSecret { get; set; } = null!;
    public string RedirectUri { get; set; } = null!;
}