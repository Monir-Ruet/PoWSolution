using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AspNet.Security.OAuth.GitHub;
using Authentication.Configuration;
using Authentication.Models.AuthModel;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace Authentication.Services;

public class OAuthService(AppConfiguration configuration)
{
    public async Task<OAuthTokenResponse?> ExchangeCodeForAccessTokenAsync(string code, Provider provider)
    {
        var (authConfiguration, tokenEndPoint) = provider switch
        {
            Provider.Google => (configuration.Authentication.Google, GoogleDefaults.TokenEndpoint),
            Provider.Github => (configuration.Authentication.Github, GitHubAuthenticationDefaults.TokenEndpoint),
            Provider.Facebook => (configuration.Authentication.Facebook, FacebookDefaults.TokenEndpoint),
            _ => throw new ArgumentException("Unsupported provider", nameof(provider))
        };
        if (string.IsNullOrEmpty(code))
            return null;
        var data = new
        {
            client_id = authConfiguration.ClientId,
            client_secret = authConfiguration.ClientSecret,
            code,
            grant_type = "authorization_code",
            redirect_uri = authConfiguration.RedirectUri
        };
        var json = JsonSerializer.Serialize(data);
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        
        using HttpClient httpClient = new HttpClient();
        var response = await httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, tokenEndPoint)
            {
                Headers =
                {
                    Accept =
                    {
                        new MediaTypeWithQualityHeaderValue("application/json")
                    },
                },
                Content = content
            });
        
        var accessTokenDocument = await response.Content.ReadAsStringAsync();
        var oauthTokenResponse = response.IsSuccessStatusCode ? OAuthTokenResponse.Success(JsonDocument.Parse(accessTokenDocument)) : null;
        return oauthTokenResponse;
    }
}