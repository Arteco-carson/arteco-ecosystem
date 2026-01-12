using Microsoft.EntityFrameworkCore;
using FineArtApi.Data;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.OpenApi.Models;
using System.Text.Json;
using FineArtApi.Services;

var builder = WebApplication.CreateBuilder(args);

// --- 1. AUTHENTICATION SERVICES (ISO27001 Compliance) ---
builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var jwtKey = builder.Configuration["Jwt:Key"];
    if (!builder.Environment.IsDevelopment())
    {
        if (string.IsNullOrEmpty(jwtKey) || jwtKey == "SuperSecretKeyForDevelopmentOnly12345!")
        {
            throw new InvalidOperationException("A strong JWT key must be configured for production environments.");
        }
    }

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        // Ensure this matches AuthController SecretKey
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey ?? "SuperSecretKeyForDevelopmentOnly12345!")),
        ValidateIssuer = false,
        ValidateAudience = false,
        //ClockSkew = TimeSpan.Zero 
    };

    // IT Operations Diagnostics: Log authentication failures for governance oversight
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            Console.WriteLine("Governance/Auth Failure: " + context.Exception.Message);
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddCors(options => {
    options.AddPolicy("AllowAll", policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

builder.Services.AddControllers().AddJsonOptions(options => {
    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase; 
});

builder.Services.AddDbContext<ArtContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register the Audit Service
builder.Services.AddScoped<IAuditService, AuditService>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Always enable Swagger and SwaggerUI for API documentation and testing
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Fine Art API V1");
});

if (app.Environment.IsDevelopment())
{
    // Development-specific configurations can go here
}

app.UseStaticFiles(); // Serve files from wwwroot
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

// Triggering deployment