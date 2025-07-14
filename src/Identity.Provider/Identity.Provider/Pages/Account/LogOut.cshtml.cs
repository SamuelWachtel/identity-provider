using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Server.AspNetCore;

public class LogoutModel : PageModel
{
    public void OnGet()
    {
        // Show confirmation form
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        // Sign out local cookie
        await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

        // Then trigger OpenIddict sign-out
        return SignOut(new AuthenticationProperties
        {
            RedirectUri = "/"
        }, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}