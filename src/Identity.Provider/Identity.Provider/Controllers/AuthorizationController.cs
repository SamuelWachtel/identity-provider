using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
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

        if (!User.Identity?.IsAuthenticated ?? true)
        {
            var returnUrl = Request.Path + QueryString.Create(Request.Query);
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new Microsoft.AspNetCore.Authentication.AuthenticationProperties
                {
                    RedirectUri = returnUrl
                });
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
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

    [HttpGet("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        var response = HttpContext.GetOpenIddictServerResponse();

        if (request == null || string.IsNullOrEmpty(request.PostLogoutRedirectUri))
        {
            return BadRequest("Invalid logout request.");
        }
        Response.Cookies.Delete(".AspNetCore.Identity.Application");

        //await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); 
        await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme); // "Identity.Application"

        return SignOut(new AuthenticationProperties
        {
            RedirectUri = request.PostLogoutRedirectUri
        }, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}