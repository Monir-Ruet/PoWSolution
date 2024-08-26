using Newtonsoft.Json;

namespace Authentication.Models.AuthModel;

public class RegisterModel
{
    [JsonProperty("email")]
    public required string Email { get; set; } 
    
    [JsonProperty("password")]
    public required string Password { get; set; } 
    
    [JsonProperty("confirmPassword")]
    public required string ConfirmPassword { get; set; }
}