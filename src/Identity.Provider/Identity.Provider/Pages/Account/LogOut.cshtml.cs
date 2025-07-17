using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Server.AspNetCore;

namespace IdentityProvider.Pages.Account;

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