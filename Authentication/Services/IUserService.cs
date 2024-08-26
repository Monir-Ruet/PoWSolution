using Authentication.Models;
using Authentication.Models.AuthModel;

namespace Authentication.Services;

public interface IUserService
{

    Task<JsonResponseResult> RegisterUserAsync(RegisterModel model);

    Task<JsonResponseResult> LoginUserAsync(LoginModel model);

    Task<JsonResponseResult> ConfirmEmailAsync(string email, string token);

    Task<JsonResponseResult> ForgetPasswordAsync(string email);

    Task<JsonResponseResult> ResetPasswordAsync(ResetPasswordModel model);
    Task<JsonResponseResult> GetConfirmationEmail(string email);
}