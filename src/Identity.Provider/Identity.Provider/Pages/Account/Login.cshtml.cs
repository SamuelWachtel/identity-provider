using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace IdentityProvider.Pages.Account;

[ValidateAntiForgeryToken]
public class LoginModel : PageModel
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public LoginModel(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ReturnUrl { get; set; }

    public class InputModel
    {
        [Required] public string Username { get; set; } = "";
        [Required] public string Password { get; set; } = "";
    }

    public void OnGet(string? returnUrl = null)
    {
        ReturnUrl = returnUrl ?? "/";
    }
    
    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        ReturnUrl = returnUrl ?? "/";

        if (!ModelState.IsValid)
        {
            var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
            // Log errors or inspect in debugger
            foreach(var error in errors)
            {
                Console.WriteLine(error);
            }
            return Page();
        }

        var user = await _userManager.FindByNameAsync(Input.Username);
        if (user == null || !await _userManager.CheckPasswordAsync(user, Input.Password))
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }

        // ✅ Important: This signs in the user with the correct Identity scheme
        await _signInManager.SignInAsync(user, isPersistent: false);

        return LocalRedirect(ReturnUrl);
    }
}
