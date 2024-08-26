using System.ComponentModel.DataAnnotations;

namespace Authentication.Models.AuthModel;

public class LoginModel
{
    [Required] public string Email { get; set; } = null!;
    [Required] public string Password { get; set; } = null!;
    public bool RememberMe { get; set; } = default;
}