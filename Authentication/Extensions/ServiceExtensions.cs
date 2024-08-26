using System.ComponentModel.DataAnnotations;
using System.Text;
using AspNet.Security.OAuth.GitHub;
using Authentication.Configuration;
using Authentication.Helper;
using Authentication.Models.DapperIdentity;
using Authentication.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Extensions;

public static class ServiceExtensions
{
    internal static IServiceCollection ConfigureService(this IServiceCollection service, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(service, nameof (service));
        var appConfiguration = new AppConfiguration();
        configuration.Bind(appConfiguration);
        
        // Validate AppConfiguration Data Annotations.
        var validationContext = new ValidationContext(appConfiguration);
        Validator.ValidateObject(appConfiguration, validationContext, validateAllProperties: true);
        
        // Add AppConfiguration to Service.
        service.AddSingleton(appConfiguration);
        
        // Add Dapper Store to the Service.
        service.AddIdentity<ApplicationUser, ApplicationRole>(options =>
        {
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // Lockout time
            options.Lockout.MaxFailedAccessAttempts = 5; // Max failed attempts before lockout
            options.Lockout.AllowedForNewUsers = true; // Allow lockout for new users
        })
        .AddDapperStores(options =>
        { 
            options.ConnectionString = appConfiguration.ConnectionStrings.DefaultConnection; 
        })
        .AddDefaultTokenProviders();
        
        
        // Cookie
        service.ConfigureApplicationCookie(options =>
        {
            options.Cookie.Name = "_app_sc_";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
            options.SlidingExpiration = true;
        });


        service.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
        {
            options.Events = new JwtBearerEvents()
            {
                OnMessageReceived = (ctx =>
                {
                    if (ctx.HttpContext.Request.Cookies.ContainsKey("_app_sc_"))
                    {
                        ctx.Token = ctx.HttpContext.Request.Cookies["_app_sc_"];
                    }
                    else if (ctx.HttpContext.Request.Query.ContainsKey("access_token"))
                    {
                        ctx.Token = ctx.HttpContext.Request.Query["access_token"];
                    }
    
                    return Task.CompletedTask;
                })
            };
            options.MapInboundClaims = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = appConfiguration.AuthSettings.Audience,
                ValidIssuer = appConfiguration.AuthSettings.Issuer,
                RequireExpirationTime = true,
                IssuerSigningKey =
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(appConfiguration.AuthSettings.Key)),
                ValidateIssuerSigningKey = true
            };
        })
        .AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
        {
            options.ClientId = appConfiguration.Authentication.Google.ClientId;
            options.ClientSecret = appConfiguration.Authentication.Google.ClientSecret;
            options.CallbackPath = "/signin-google";
        })
        .AddGitHub(GitHubAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.ClientId = appConfiguration.Authentication.Github.ClientId;
            options.ClientSecret = appConfiguration.Authentication.Github.ClientSecret;
            options.CallbackPath = "/signin-github";
            options.Scope.Add("user:email");
        })
        .AddFacebook(FacebookDefaults.AuthenticationScheme, options =>
        {
            options.ClientId = appConfiguration.Authentication.Facebook.ClientId;
            options.ClientSecret = appConfiguration.Authentication.Facebook.ClientSecret;
            options.CallbackPath = "/signin-facebook";
        });
            
        service.AddAuthorization(options =>
        {
            options.DefaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(
                    [JwtBearerDefaults.AuthenticationScheme, "Identity.Application"]).Build();
        });
        
        service.AddScoped<IUserService, UserService>();
        service.AddScoped<IMailService, MailService>();
        service.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();
        service.AddScoped<OAuthService>();
        return service; 
    }
}