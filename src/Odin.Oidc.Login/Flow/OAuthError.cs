using System.Text.Json;

namespace Odin.Oidc.Login.Flow;

/// <summary>An OAuth error as words: "error: description", or the error alone, or a body that is not one.</summary>
public static class OAuthError
{
    public static string Describe(string error, string? description) =>
        string.IsNullOrEmpty(description) ? error : $"{error}: {description}";

    /// <summary>A JSON error body ({"error", "error_description"}, RFC 6749); anything else is shown as is.</summary>
    public static string Describe(string body)
    {
        try
        {
            using var json = JsonDocument.Parse(body);
            return json.RootElement.ValueKind == JsonValueKind.Object
                   && json.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String
                ? Describe(error.GetString()!, json.RootElement.TryGetProperty("error_description", out var d) && d.ValueKind == JsonValueKind.String ? d.GetString() : null)
                : body;
        }
        catch (JsonException)
        {
            return body;
        }
    }
}
