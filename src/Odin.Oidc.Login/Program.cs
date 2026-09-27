using Odin.Oidc.Login;

var builder = WebApplication.CreateBuilder(args);
builder.AddOdinOidcLogin();

var app = builder.Build();
app.MapOdinOidcLogin();
app.Run();

public partial class Program;
