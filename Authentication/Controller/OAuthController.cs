using System.ComponentModel.DataAnnotations;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using AspNet.Security.OAuth.GitHub;
using Authentication.Configuration;
using Authentication.Helper;
using Authentication.Models;
using Authentication.Models.AuthModel;
using Authentication.Models.DapperIdentity;
using Authentication.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;

namespace Authentication.Controller;

[Route(("api/[controller]"))]
[ApiController]
public class OAuthController(SignInManager<ApplicationUser> signInManager, 
                             UserManager<ApplicationUser> userManager,
                             AppConfiguration configuration,
                             OAuthService oAuthService,
                             IJwtTokenGenerator tokenGenerator) : ControllerBase
{
    [HttpGet("login/google")]
    public IActionResult Google()
    {
        var redirectUrl = Url.Action("Callback", "OAuth");
        var properties = signInManager.ConfigureExternalAuthenticationProperties(GoogleDefaults.AuthenticationScheme, redirectUrl);
        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }
    
    [HttpGet("login/github")]
    public IActionResult Github()
    {
        var redirectUrl = Url.Action("Callback", "OAuth");
        var properties = signInManager.ConfigureExternalAuthenticationProperties(GitHubAuthenticationDefaults.AuthenticationScheme, redirectUrl);
        return Challenge(properties, GitHubAuthenticationDefaults.AuthenticationScheme);
    }
    
    [HttpGet("callback")]
    public async Task<IActionResult> Callback()
    {
        var info = await signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return BadRequest("Error loading external login information.");
        }
        
        var user = new ApplicationUser() { UserName = info.Principal.FindFirstValue(ClaimTypes.Email), Email = info.Principal.FindFirstValue(ClaimTypes.Email) };
        var targetUrl = $"{configuration.ViewUrl}";
        var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
        if (result.Succeeded)
            return Redirect(targetUrl);
        var identityResult = await userManager.CreateAsync(user);
        if (!identityResult.Succeeded) return BadRequest("Error creating or logging in user.");
        
        identityResult = await userManager.AddLoginAsync(user, info);
        
        if (!identityResult.Succeeded) return BadRequest("Error creating or logging in user.");
        
        await signInManager.SignInAsync(user, isPersistent: false);
        
        return Redirect(targetUrl);
    }
    
    [HttpGet("validate/{provider}")]
    public async Task<IActionResult> ValidateOAuth([FromRoute] Provider provider, [FromQuery][Required] string code)
    {
        try
        {
            var providers = new HashSet<Provider>() { Provider.Google, Provider.Github, Provider.Facebook };
            if (!providers.Contains(provider))
                throw new HttpException(StatusCodes.Status400BadRequest, "Invalid provider.");
            
            var oAuthTokenResponse = await oAuthService.ExchangeCodeForAccessTokenAsync(code, provider);

            if (string.IsNullOrEmpty(oAuthTokenResponse?.AccessToken))
                throw new HttpException(StatusCodes.Status400BadRequest, "Invalid code to fetch access token from the provider.");

            var accessToken = oAuthTokenResponse.AccessToken;

            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("MyApp");

            var userInformationEndpoint = provider switch
            {
                Provider.Google => GoogleDefaults.UserInformationEndpoint,
                Provider.Github => GitHubAuthenticationDefaults.UserInformationEndpoint,
                Provider.Facebook => FacebookDefaults.UserInformationEndpoint,
                _ => throw new ArgumentException("Unsupported provider", nameof(provider))
            };

            if (provider == Provider.Facebook)
            {
                var queryString = new Dictionary<string, string?>()
                {
                    { "fields", "id,name,email,picture" }
                };
                userInformationEndpoint = QueryHelpers.AddQueryString(userInformationEndpoint, queryString);
            }

            var request = new HttpRequestMessage(provider == Provider.Github ? HttpMethod.Get : HttpMethod.Post, userInformationEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var response = await httpClient.SendAsync(request);

            var identity = new ClaimsIdentity();
            var principal = new ClaimsPrincipal(identity);

            if (!response.IsSuccessStatusCode)
                throw new HttpException("An error occurred while retrieving the user profile.");
            
            var userResponse = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(userResponse);
            var userJsonElement = document.RootElement;
            var (id, name, givenName, picture, email) = provider switch
            {
                Provider.Facebook => (userJsonElement.GetString("id"), userJsonElement.GetString("name"),
                    userJsonElement.GetString("given_name"), userJsonElement.GetProperty("picture")
                        .GetProperty("data")
                        .GetProperty("url").GetString(), userJsonElement.GetString("email")),
                Provider.Github => (userJsonElement.GetString("id"), userJsonElement.GetString("name"),
                    userJsonElement.GetString("given_name"), userJsonElement.GetString("avatar_url"), string.Empty),
                Provider.Google => (userJsonElement.GetString("sub"), userJsonElement.GetString("name"),
                    userJsonElement.GetString("given_name"), userJsonElement.GetString("picture"),
                    userJsonElement.GetString("email")),
                _ => throw new ArgumentException("Unsupported provider", nameof(provider))
            };
            identity.AddClaim(new Claim(ClaimTypes.Name, name ?? string.Empty, ClaimValueTypes.String));
            identity.AddClaim(new Claim(ClaimTypes.GivenName, givenName ?? string.Empty, ClaimValueTypes.String));

            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, id ?? string.Empty, ClaimValueTypes.String));
            identity.AddClaim(new Claim("picture", picture ?? string.Empty, ClaimValueTypes.String));
            if (provider != Provider.Github)
                identity.AddClaim(new Claim(ClaimTypes.Email, email ?? string.Empty, ClaimValueTypes.String));

            if (provider == Provider.Github)
            {
                request = new HttpRequestMessage(HttpMethod.Get, GitHubAuthenticationDefaults.UserEmailsEndpoint);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                response = await httpClient.SendAsync(request);
                var emailResponse = await response.Content.ReadAsStringAsync();
                
                var emailInformation = JsonConvert.DeserializeObject<List<GithubEmailModel>>(emailResponse);
                email = emailInformation?.FirstOrDefault(e => e.Primary)?.Email;
                if (!string.IsNullOrEmpty(email))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Email, email, ClaimValueTypes.String));
                }
            }

            var providerKey = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            var info = new ExternalLoginInfo(principal, provider.ToString(), providerKey!, provider.ToString());

            var user = await userManager.FindByLoginAsync(provider.ToString(), providerKey!);
            if (user is not null)
            {
                var token = tokenGenerator.GenerateJwtToken(user);
                return StatusCode(StatusCodes.Status200OK, new JsonResponseResult<object>(true,
                    $"{provider.ToString()} login successfull.", new
                    {
                        Token = token
                    }));
            }
            
            if(string.IsNullOrEmpty(email))
                throw new HttpException("An error occurred while retrieving the email address associated to the user profile.");
            user = new ApplicationUser()
            {
                Email = principal.FindFirst(claim => claim.Type == ClaimTypes.Email)?.Value,
                UserName = principal.FindFirst(claim => claim.Type == ClaimTypes.Email)?.Value
            };

            var userExist = await userManager.FindByEmailAsync(email);
            if (userExist != null)
                throw new HttpException(StatusCodes.Status409Conflict, "There is an account with the email address");
            
            var identityResult = await userManager.CreateAsync(user);
            if (!identityResult.Succeeded)
                throw new HttpException(StatusCodes.Status409Conflict, "An error occured adding a new user.");

            identityResult = await userManager.AddLoginAsync(user, info);
            if (!identityResult.Succeeded)
                throw new HttpException(StatusCodes.Status409Conflict, "An error occured adding the user provider login information associated to the user profile.");
            
            var tokenAsString = tokenGenerator.GenerateJwtToken(user);
            return StatusCode(StatusCodes.Status200OK, new JsonResponseResult<object>(true, $"{provider.ToString()} login successfull.",
                new
                {
                    Token = tokenAsString
                }));
        }
        
        catch (HttpException ex)
        {
            return StatusCode(ex.Status, new JsonResponseResult<object>(false, ex.Message, new
            {
                Errors = ex.Errors?.ToList()
            }));
        }
        catch (Exception)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new JsonResponseResult(false, "An error occured."));
        }
    }
}