namespace IdentityProvider.Data;

public class OpenIdDictClientSettings
{
    public List<string> RedirectUris { get; set; } = new();
    public List<string> PostLogoutRedirectUris { get; set; } = new();
    public string ClientId { get; set; } = "my-public-client";
}