using System.Net;
using System.Net.Mail;
using Authentication.Configuration;

namespace Authentication.Services;

public class MailService(AppConfiguration configuration) : IMailService
{
    public async Task SendEmailAsync(string toEmail, string subject, string body)
    {
        var mail = new MailMessage();
        mail.From = new MailAddress(configuration.MailConfiguration.Email);
        mail.To.Add(toEmail);
        mail.Subject = subject;
        mail.Body = body;
        mail.IsBodyHtml = true;
        
        var smtpClient = new SmtpClient(configuration.MailConfiguration.Server)
        {
            Port = 587,
            Credentials = new NetworkCredential(configuration.MailConfiguration.Email, configuration.MailConfiguration.Password),
            EnableSsl = true,
        };

        await smtpClient.SendMailAsync(mail);
    }
}