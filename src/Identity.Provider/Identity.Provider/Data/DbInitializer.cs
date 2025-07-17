using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityProvider.Data;

public static class DbInitializer
{
    public static async Task SeedAsync(IServiceProvider serviceProvider, OpenIdDictClientSettings settings)
    {
        var appManager = serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var client = await appManager.FindByClientIdAsync(settings.ClientId);

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = settings.ClientId,
            ClientType = ClientTypes.Public,
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession,

                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.Password,
                Permissions.GrantTypes.ClientCredentials,
                Permissions.GrantTypes.TokenExchange,
                Permissions.GrantTypes.RefreshToken,
                Permissions.GrantTypes.Implicit,

                Permissions.ResponseTypes.Code,
                Scopes.OpenId,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Email
            },
            Requirements =
            {
                Requirements.Features.ProofKeyForCodeExchange
            }
        };

        foreach (var uri in settings.RedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(uri));
        }

        foreach (var uri in settings.PostLogoutRedirectUris)
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(uri));
        }

        if (client == null)
        {
            await appManager.CreateAsync(descriptor);
        }
        else
        {
            await appManager.UpdateAsync(client, descriptor);
        }

        var userManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var userName = "user";
        var password = "Pass123$";

        var user = await userManager.FindByNameAsync(userName);
        if (user == null)
        {
            user = new IdentityUser
            {
                UserName = userName,
                Email = "user@example.com",
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                throw new Exception($"Failed to create seed user: {errors}");
            }
        }

        var registeredClient = await appManager.FindByClientIdAsync(settings.ClientId);
        var uris = await appManager.GetPostLogoutRedirectUrisAsync(registeredClient);

        Console.WriteLine("==== Registered Post Logout Redirect URIs ====");
        foreach (var uri in uris)
        {
            Console.WriteLine(uri);
        }
    }
}
