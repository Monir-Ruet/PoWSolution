using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace Authentication.Models.AuthModel;

public class ResetPasswordModel
{
    [JsonProperty("token")]
    [Required] public string Token { get; set; } = null!;
    
    [JsonProperty("email")]
    [Required] [EmailAddress] public string Email { get; set; } = null!;
    
    [JsonProperty("newPassword")]
    [Required] public string NewPassword { get; set; } = null!;

    [JsonProperty("confirmPassword")]
    [Required] public string ConfirmPassword { get; set; } = null!;
}