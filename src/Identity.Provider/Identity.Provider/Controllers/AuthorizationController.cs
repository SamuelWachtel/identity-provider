using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityProvider.Controllers;

public class AuthorizationController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;

    public AuthorizationController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost("~/connect/token")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("OpenIddict request is null");

        if (request.IsPasswordGrantType())
        {
            var user = await _userManager.FindByNameAsync(request.Username!);
            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password!))
            {
                return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            principal.SetScopes(request.GetScopes());
            principal.SetResources("erp_api");

            principal.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user));
            principal.SetClaim(Claims.Name, user.UserName!);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        else if (request.IsAuthorizationCodeGrantType())
        {
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            if (result?.Principal != null)
            {
                return SignIn(result.Principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            else if (result?.Failure != null)
            {
                return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            return BadRequest(new { error = "invalid_grant" });
        }
        return BadRequest(new { error = "unsupported_grant_type" });
    }

    [HttpGet("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("OpenIddict request is null");

        // If user is not authenticated, redirect to login page
        if (!User.Identity?.IsAuthenticated ?? true)
        {
            // Redirect to your login page, preserving the original return URL
            var returnUrl = Request.Path + QueryString.Create(Request.Query);
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new Microsoft.AspNetCore.Authentication.AuthenticationProperties
                {
                    RedirectUri = returnUrl
                });
        }

        // User is authenticated, create claims principal for the authorization code
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var principal = await _signInManager.CreateUserPrincipalAsync(user);

        // Set scopes requested by client
        principal.SetScopes(request.GetScopes());
        principal.SetResources("erp_api");

        // Claims required by OpenID Connect
        principal.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user));
        principal.SetClaim(Claims.Name, user.UserName!);

        // Returning SignIn issues the authorization code
        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        var response = HttpContext.GetOpenIddictServerResponse();

        if (request == null || string.IsNullOrEmpty(request.PostLogoutRedirectUri))
        {
            return BadRequest("Invalid logout request.");
        }

        // Optionally: sign out the user
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); 
        //await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

        // Redirect to the original post-logout URI
        return SignOut(new AuthenticationProperties
        {
            RedirectUri = request.PostLogoutRedirectUri
        }, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}