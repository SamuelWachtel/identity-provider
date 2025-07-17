using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace IdentityProvider.Emailing;

public class EmailSender : IEmailSender
{
    public Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        Console.WriteLine($"Sending email to {email}: {subject} - {htmlMessage}");
        return Task.CompletedTask;
    }
}