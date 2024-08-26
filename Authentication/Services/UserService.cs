using System.Net;
using System.Text;
using Authentication.Configuration;
using Authentication.Helper;
using Authentication.Models;
using Authentication.Models.AuthModel;
using Authentication.Models.DapperIdentity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;

namespace Authentication.Services;

public class UserService(UserManager<ApplicationUser> userManager,
                         SignInManager<ApplicationUser> signInManager,
                         AppConfiguration configuration, 
                         IMailService mailService,
                         IJwtTokenGenerator tokenGenerator) : IUserService
{
    public async Task<JsonResponseResult> RegisterUserAsync(RegisterModel model)
    {
        if (model.Password != model.ConfirmPassword)
        {
            return new JsonResponseResult(true, "Password and Confirm Password does not match.", HttpStatusCode. BadRequest);
        }

        var user = new ApplicationUser()
        {
            Email = model.Email,
            UserName = model.Email,
        };

        var registerUserResult = await userManager.CreateAsync(user, model.Password);

        if (!registerUserResult.Succeeded)
        {
            return new JsonResponseResult<object>(false, "Could not register the user.", HttpStatusCode.Conflict, new 
            {
                Errors = registerUserResult.Errors.Select(e => e.Description).ToList() 
            });
        }

        await SendEmailConfirmationUrl(user);
        
        return new JsonResponseResult(true, "Account created successfully.", HttpStatusCode.OK);

    }
    
    public async Task<JsonResponseResult> LoginUserAsync(LoginModel model)
    {
        var user = await userManager.FindByEmailAsync(model.Email);
        if(user is null)
        {
            return new JsonResponseResult(false, "There is no user with this email address.", HttpStatusCode.NotFound);
        }
        else if (!user.EmailConfirmed)
        {
            return new JsonResponseResult(false, "You must confirm your email before you can log in.", HttpStatusCode.BadRequest);
        }
        var result = await signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, true);

        if (!result.Succeeded)
        {
            return new JsonResponseResult<object>(false, "Could not authenticate the user.",HttpStatusCode.Unauthorized, new
            {
                Errors = (string[])["Invalid username / password."]
            });
        }
        else if (result.IsLockedOut)
        {
            return new JsonResponseResult(false, "Account locked out due to multiple failed attempts.", HttpStatusCode.Locked);
        }
        else if (result.IsNotAllowed)
        {
            return new JsonResponseResult(false, "Account not allowed to sign in.", HttpStatusCode.Forbidden);
        }

        var tokenAsString = tokenGenerator.GenerateJwtToken(user);

        return new JsonResponseResult<object>(true, "Login successful.", HttpStatusCode.OK, new
        {
            Token = tokenAsString
        });
    }
    
    public async Task<JsonResponseResult> GetConfirmationEmail(string email)
    {
        var user = await userManager.FindByEmailAsync(email);
        if(user == null)
        {
            return new JsonResponseResult(false, "There is no user with this email address.", HttpStatusCode.NotFound);
        }
        else if (user.EmailConfirmed)
        {
            return new JsonResponseResult(false, "Email is already confirmed.", HttpStatusCode.BadRequest);
        }

        await SendEmailConfirmationUrl(user);
        
        return new JsonResponseResult(true, "A confirmation URL has been sent to the email address.",
            HttpStatusCode.OK);
    }
    public async Task<JsonResponseResult> ConfirmEmailAsync(string email, string token)
    {
        var user = await userManager.FindByEmailAsync(email);
        if(user == null)
        {
            return new JsonResponseResult(false, "There is no user with this email address.", HttpStatusCode.NotFound);
        }

        var decodedToken = WebEncoders.Base64UrlDecode(token);
        var normalToken = Encoding.UTF8.GetString(decodedToken);

        var result = await userManager.ConfirmEmailAsync(user, normalToken);

        if (!result.Succeeded)
        {
            return new JsonResponseResult<object>(false, "Could not confirm the email.", HttpStatusCode.InternalServerError, new
            {
                Errors = result.Errors.Select(e => e.Description)
            });
        }

        return new JsonResponseResult(true, "Email confirmed successfully.", HttpStatusCode.OK);
    }
    
    public async Task<JsonResponseResult> ForgetPasswordAsync(string email)
    {
        var user = await userManager.FindByEmailAsync(email);
        if(user == null)
        {
            return new JsonResponseResult(false, "There is no user with this email address.", HttpStatusCode.NotFound);
        }

        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = Encoding.UTF8.GetBytes(token);
        var validToken = WebEncoders.Base64UrlEncode(encodedToken);

        var url = $"{configuration.AppUrl}/api/auth/ResetPassword?email={email}&token={validToken}";

        await mailService.SendEmailAsync(email, "Reset Password", 
            $"""
                <h1>Follow the instructions to reset your password</h1>
                <p>To reset your password <a href='{url}'>Click here</a></p>
             """
        );

        return new JsonResponseResult(true, "A reset URL has been sent to the email address.",
                HttpStatusCode.OK);
    }

    public async Task<JsonResponseResult> ResetPasswordAsync(ResetPasswordModel model)
    {
        var user = await userManager.FindByEmailAsync(model.Email);
        if(user == null)
        {
            return new JsonResponseResult(false, "There is no user with this email address.", HttpStatusCode.NotFound);
        }

        if (model.NewPassword != model.ConfirmPassword)
        {
            return new JsonResponseResult(false, "Password doesn't match its confirmation",
                HttpStatusCode.BadRequest);
        }

        var decodedToken = WebEncoders.Base64UrlDecode(model.Token);
        var normalToken = Encoding.UTF8.GetString(decodedToken);

        var result = await userManager.ResetPasswordAsync(user, normalToken, model.NewPassword);

        return result.Succeeded ? new JsonResponseResult(true, "Password reset successful.", HttpStatusCode.OK) : 
            new JsonResponseResult(false, "Failed to reset password, Please try again.", HttpStatusCode.BadRequest);
    }
    private async Task SendEmailConfirmationUrl(ApplicationUser user)
    {
        var confirmEmailToken = await userManager.GenerateEmailConfirmationTokenAsync(user);

        var encodedEmailToken = Encoding.UTF8.GetBytes(confirmEmailToken);
        var validEmailToken = WebEncoders.Base64UrlEncode(encodedEmailToken);

        var url = $"{configuration.AppUrl}/api/auth/ConfirmEmail?email={user.Email}&token={validEmailToken}";

        await mailService.SendEmailAsync(user.Email ?? throw new ArgumentNullException(user.Email), "Confirm your email",
            $"""
                        <h1>Welcome to Auth Demo</h1>
                        <p>Please confirm your email by <a href='{url}'>Clicking here</a></p>
             """
        );
    }
    
}