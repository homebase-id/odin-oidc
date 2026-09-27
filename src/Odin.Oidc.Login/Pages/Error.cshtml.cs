using System.Diagnostics;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Odin.Oidc.Login.Pages;

public sealed class ErrorModel : PageModel
{
    public string? RequestId { get; private set; }

    public void OnGet()
    {
        RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
    }
}
