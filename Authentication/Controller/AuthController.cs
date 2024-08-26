using System.ComponentModel.DataAnnotations;
using System.Net;
using Authentication.Configuration;
using Authentication.Models;
using Authentication.Models.AuthModel;
using Authentication.Services;
using Microsoft.AspNetCore.Mvc;

namespace Authentication.Controller;

[ApiController]
[Route("api/[controller]/[action]")]
public class AuthController(IUserService userService, 
                            IMailService mailService, 
                            AppConfiguration configuration) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
    {
        if (!ModelState.IsValid)
        {
            return StatusCode(StatusCodes.Status400BadRequest, new JsonResponseResult(false, "Please provide valid registration data."));
        }

        var registerResult = await userService.RegisterUserAsync(model);
        

        return StatusCode((int)registerResult.StatusCode, registerResult);
    }

    [HttpPost]
    public async Task<IActionResult> LoginAsync([FromBody] LoginModel model)
    {
        if (!ModelState.IsValid)
        {
            return StatusCode(StatusCodes.Status400BadRequest, new JsonResponseResult<object>(false, "Please provide all the required fields.", (HttpStatusCode) StatusCodes.Status400BadRequest,new
            {
                Errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList()
            }));
        }

        var loginResult = await userService.LoginUserAsync(model);
        return StatusCode((int)loginResult.StatusCode, loginResult);
    }

    [HttpGet]
    public async Task<IActionResult> GetEmailConfirmationUrl([FromQuery] [Required] string email)
    {
        if (string.IsNullOrEmpty(email))
        {
            return StatusCode(StatusCodes.Status400BadRequest, new JsonResponseResult(false, "Email address can not be empty or null."));
        }
        var emailConfirmationResult = await userService.GetConfirmationEmail(email);
        return StatusCode((int)emailConfirmationResult.StatusCode, emailConfirmationResult);
    }
    
    [HttpGet]
    public async Task<IActionResult> ConfirmEmail([FromQuery] [Required] string email, [FromQuery] [Required] string token)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
            return StatusCode(StatusCodes.Status400BadRequest,new JsonResponseResult(false, "Please provide all the required field."));

        var confirmEmailResult = await userService.ConfirmEmailAsync(email, token);
        
        return StatusCode((int)confirmEmailResult.StatusCode, confirmEmailResult);
    }
    
    [HttpGet]
    public async Task<IActionResult> ForgetPassword([FromQuery][Required] string email)
    {
        if (string.IsNullOrEmpty(email))
        {
            return StatusCode(StatusCodes.Status400BadRequest, new JsonResponseResult<object>(false, "Please provide email.",new
            {
                errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList()
            }));
        }

        var result = await userService.ForgetPasswordAsync(email);
        return StatusCode((int)result.StatusCode, result);
    }
    
    [HttpPost]
    public async Task<IActionResult> ResetPassword([FromBody]ResetPasswordModel model)
    {
        if (!ModelState.IsValid)
        {
            return StatusCode(StatusCodes.Status400BadRequest,
                new JsonResponseResult(false, "Please provide all the required field."));
        }
        
        var resetPasswordResult = await userService.ResetPasswordAsync(model);
        return StatusCode((int)resetPasswordResult.StatusCode, resetPasswordResult);
    }
}