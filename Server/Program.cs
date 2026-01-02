using Microsoft.AspNetCore.OData;
using Microsoft.AspNetCore.OData.Routing.Conventions;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.OData.ModelBuilder;
using Radzen;
using Microsoft.OData.Edm;
using SmartNest.Server.Data;
using SmartNest.Server.Services;
using SmartNest.Server.Hubs;
using SmartNest.Server.Models.postgres;
using Microsoft.AspNetCore.Identity;
using SmartNest.Server.Models;
using Microsoft.AspNetCore.Components.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Configurer le port dynamique de Render
var port = Environment.GetEnvironmentVariable("PORT") ?? "5001";
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

// =========================================
// 🔧 Services de base
// =========================================
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// =========================================
// 🧩 Services Radzen
// =========================================
builder.Services.AddScoped<DialogService>();
builder.Services.AddScoped<Radzen.NotificationService>();
builder.Services.AddScoped<TooltipService>();
builder.Services.AddScoped<ContextMenuService>();

// =========================================
// 🌐 HTTP Client (auto-baseAddress)
// =========================================
builder.Services.AddSingleton(sp =>
{
    var server = sp.GetRequiredService<IServer>();
    var addressFeature = server.Features.Get<IServerAddressesFeature>();
    string baseAddress = addressFeature!.Addresses.First();
    return new HttpClient
    {
        BaseAddress = new Uri(baseAddress)
    };
});

// =========================================
// 🗄️ Configuration des bases de données
// =========================================
Console.WriteLine("========== 🔍 CONFIGURATION DEBUG ==========");
Console.WriteLine($"Environment: {builder.Environment.EnvironmentName}");
Console.WriteLine($"ContentRootPath: {builder.Environment.ContentRootPath}");

// Récupérer la connection string
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
var postgresConnectionString = builder.Configuration.GetConnectionString("postgresConnection");

Console.WriteLine($"🔗 DefaultConnection: {connectionString ?? "NULL"}");
Console.WriteLine($"🔗 PostgresConnection: {postgresConnectionString ?? "NULL"}");

// Afficher toutes les ConnectionStrings disponibles
Console.WriteLine("\n📋 Toutes les ConnectionStrings:");
var connectionStrings = builder.Configuration.GetSection("ConnectionStrings");
foreach (var child in connectionStrings.GetChildren())
{
    Console.WriteLine($"  ✓ {child.Key} = {child.Value}");
}
Console.WriteLine("============================================\n");

// Validation
if (string.IsNullOrEmpty(connectionString))
{
    Console.WriteLine("⚠️ DefaultConnection manquante, tentative de récupération depuis les variables d'environnement...");
    connectionString = builder.Configuration["ConnectionStrings__DefaultConnection"];
    
    if (string.IsNullOrEmpty(connectionString))
    {
        throw new InvalidOperationException("❌ ERREUR CRITIQUE: Aucune chaîne de connexion trouvée!");
    }
    
    Console.WriteLine($"✅ Connection string récupérée: {connectionString}");
}

// =========================================
// 📦 Contextes de base de données
// =========================================


// Configuration de la base de données
var databaseUrl = Environment.GetEnvironmentVariable("DATABASE_URL");

if (!string.IsNullOrEmpty(databaseUrl))
{
    // Production : Render
    var connectiondbString = ConvertDatabaseUrl(databaseUrl);
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseNpgsql(connectiondbString));
}
else
{
    // Développement : local
    var connectiondbString = builder.Configuration.GetConnectionString("DefaultConnection");
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseNpgsql(connectiondbString));
}
// =========================================
// 🧠 Services métier
// =========================================

// Configuration Email
builder.Services.Configure<EmailSettings>(
    builder.Configuration.GetSection("EmailSettings"));
builder.Services.AddScoped<IEmailService, EmailService>();

// Configuration SMS
builder.Services.Configure<SmsSettings>(
    builder.Configuration.GetSection("SmsSettings"));
builder.Services.AddHttpClient();
builder.Services.AddScoped<ISmsService, SmsService>();

// Services
builder.Services.AddScoped<SmartNest.Server.postgresService>();
builder.Services.AddSingleton<MqttService>();
builder.Services.AddSingleton<IYoloProcessManager, YoloProcessManager>();
builder.Services.AddHostedService<YoloServerHostedService>();
builder.Services.AddScoped<INotificationService, NotificationUIService>();
builder.Services.AddScoped<INotificationSettingsService, NotificationSettingsService>();
builder.Services.AddScoped<INotificationDispatcherService, NotificationDispatcherService>();
builder.Services.AddScoped<IVideoStreamService, VideoStreamService>();
builder.Services.AddScoped<IChickMonitoringService, ChickMonitoringService>();
builder.Services.AddScoped<IYoloAnalysisService, YoloAnalysisService>();
builder.Services.AddHostedService<NotificationMonitoringService>();

// HTTP Clients
builder.Services.AddHttpClient<IYoloAnalysisService, YoloAnalysisService>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
});

builder.Services.AddHttpClient<IVideoStreamService, VideoStreamService>(client =>
{
    client.BaseAddress = new Uri(builder.Configuration["BaseUrl"] ?? "https://localhost:7001/");
});

builder.Services.AddHttpClient("SmartNest.Server").AddHeaderPropagation(o => o.Headers.Add("Cookie"));
builder.Services.AddHeaderPropagation(o => o.Headers.Add("Cookie"));

// =========================================
// ⚡ SignalR
// =========================================
builder.Services.AddSignalR();

// =========================================
// 📦 OData Configuration
// =========================================
builder.Services.AddControllers().AddOData(opt =>
{
    // OData PostgreSQL
    var postgresBuilder = new ODataConventionModelBuilder();
    postgresBuilder.EntitySet<SmartNest.Server.Models.postgres.Chick>("Chicks");
    postgresBuilder.EntitySet<SmartNest.Server.Models.postgres.ChickStatistics>("ChickStatistics");
    postgresBuilder.EntitySet<SmartNest.Server.Models.postgres.device>("Devices");
    postgresBuilder.EntitySet<SmartNest.Server.Models.postgres.Notification>("Notifications");
    postgresBuilder.EntitySet<SmartNest.Server.Models.postgres.Sensordatum>("Sensordata");

    opt.AddRouteComponents("odata/postgres", postgresBuilder.GetEdmModel())
        .Select().Filter().OrderBy().Expand().Count().SetMaxTop(100).TimeZone = TimeZoneInfo.Utc;
    
    // OData Identity
    var oDataBuilder = new ODataConventionModelBuilder();
    oDataBuilder.EntitySet<ApplicationUser>("ApplicationUsers");
    var usersType = oDataBuilder.StructuralTypes.First(x => x.ClrType == typeof(ApplicationUser));
    usersType.AddProperty(typeof(ApplicationUser).GetProperty(nameof(ApplicationUser.Password)));
    usersType.AddProperty(typeof(ApplicationUser).GetProperty(nameof(ApplicationUser.ConfirmPassword)));
    oDataBuilder.EntitySet<ApplicationRole>("ApplicationRoles");
    oDataBuilder.EntitySet<ApplicationTenant>("ApplicationTenants");
    
    opt.AddRouteComponents("odata/Identity", oDataBuilder.GetEdmModel())
        .Count().Filter().OrderBy().Expand().Select().SetMaxTop(null).TimeZone = TimeZoneInfo.Utc;
});

// =========================================
// 🔐 Authentication & Authorization
// =========================================
builder.Services.AddAuthentication();
builder.Services.AddAuthorization();
builder.Services.AddScoped<SmartNest.Client.SecurityService>();

// Multi-tenancy User Store
builder.Services.AddTransient<IUserStore<ApplicationUser>, MultiTenancyUserStore>();

// Authentication State Provider
builder.Services.AddScoped<AuthenticationStateProvider, SmartNest.Client.ApplicationAuthenticationStateProvider>();

// Localization
builder.Services.AddLocalization();

// Identity Configuration
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;
    
    options.User.RequireUniqueEmail = true;
    
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddSignInManager<SignInManager<ApplicationUser>>()
.AddDefaultTokenProviders();

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowBlazor", policy =>
    {
        policy.WithOrigins(
                "https://blazor-app.onrender.com",  // Votre Static Site Render
                "https://Smart-Nest.com",         // Votre domaine personnalisé
                "http://localhost:5001"              // Pour le développement local
            )
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

// Optimisation mémoire pour 512 MB
builder.Services.AddResponseCompression(options =>
{
    options.EnableForHttps = true;
});

builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 10 * 1024 * 1024; // 10 MB max
    options.Limits.MaxConcurrentConnections = 50;
});

// Cookie Configuration
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromDays(7);
    options.LoginPath = "/login";
    options.AccessDeniedPath = "/access-denied";
    options.SlidingExpiration = true;

    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = 401;
        return Task.CompletedTask;
    };
    
    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = 403;
        return Task.CompletedTask;
    };
});

// =========================================
// 🚀 Build Application
// =========================================
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// =========================================
// 🗄️ DATABASE INITIALIZATION (Docker-Ready)
// =========================================
Console.WriteLine("\n========== 🗄️ DATABASE INITIALIZATION ==========");

try
{
    // Attendre que PostgreSQL soit prêt (important pour Docker)
    Console.WriteLine("⏳ Waiting for PostgreSQL to be ready...");
    using (var scope1 = app.Services.CreateScope())
    {
        var db = scope1.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.Database.MigrateAsync();// Crée la DB si elle n'existe 
         Console.WriteLine("PostgreSQL  ready");
    }
    
    // =========================================
    // 👥 Seed Roles & Admin User
    // =========================================
    Console.WriteLine("\n👥 Initializing Roles & Admin User...");
    using var scope = app.Services.CreateScope();
    var services = scope.ServiceProvider;
    // Récupérer TOUS les contextes
    var DbContext = services.GetRequiredService<ApplicationDbContext>();
    var logger = services.GetRequiredService<ILogger<Program>>();
    
    var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
    var roleManager = services.GetRequiredService<RoleManager<ApplicationRole>>();
    
    // Créer les rôles
    string[] roleNames = { "Admin", "User", "Manager" };
    foreach (var roleName in roleNames)
    {
        if (!await roleManager.RoleExistsAsync(roleName))
        {
            var roleResult = await roleManager.CreateAsync(new ApplicationRole { Name = roleName });
            if (roleResult.Succeeded)
            {
                Console.WriteLine($"  ✅ Role '{roleName}' created");
            }
            else
            {
                Console.WriteLine($"  ❌ Failed to create role '{roleName}': {string.Join(", ", roleResult.Errors.Select(e => e.Description))}");
            }
        }
        else
        {
            Console.WriteLine($"  ℹ️ Role '{roleName}' already exists");
        }
    }
    
    // Créer l'utilisateur admin
    var adminEmail = "admin@smartnest.com";
    var adminPassword = "Admin@123";
    var adminUser = await userManager.FindByEmailAsync(adminEmail);
    
    if (adminUser == null)
    {
        adminUser = new ApplicationUser
        {
            UserName = adminEmail,
            Email = adminEmail,
            EmailConfirmed = true
        };
        
        var createResult = await userManager.CreateAsync(adminUser, adminPassword);
        
        if (createResult.Succeeded)
        {
            await userManager.AddToRoleAsync(adminUser, "Admin");
            Console.WriteLine($"✅ Admin user created successfully!");
            Console.WriteLine($"   📧 Email: {adminEmail}");
            Console.WriteLine($"   🔑 Password: {adminPassword}");
        }
        else
        {
            Console.WriteLine($"❌ Failed to create admin user:");
            foreach (var error in createResult.Errors)
            {
                Console.WriteLine($"   - {error.Description}");
            }
        }
    }
    else
    {
        Console.WriteLine($"ℹ️ Admin user already exists");
    }
    
    // Seed Tenants Admin (si la méthode existe)
    try
    {
        await DbContext!.SeedTenantsAdmin();
        Console.WriteLine("✅ Tenants seeded successfully");
    }
    catch (Exception ex)
    {
        logger.LogWarning(ex, "⚠️ Could not seed tenants (method may not exist)");
    }
    
    Console.WriteLine("============================================\n");
}
catch (Exception ex)
{
    Console.WriteLine($"\n❌ CRITICAL ERROR during database initialization:");
    Console.WriteLine($"Message: {ex.Message}");
    Console.WriteLine($"Stack Trace: {ex.StackTrace}");
    
    // En production, on peut décider de ne pas crasher l'app
    if (!app.Environment.IsDevelopment())
    {
        Console.WriteLine("⚠️ Continuing without database initialization (Production mode)");
    }
    else
    {
        throw; // En dev, on crash pour voir l'erreur
    }
}

// =========================================
// 🧭 Middleware Pipeline
// =========================================
app.MapHub<RealtimeHub>("/realtimeHub");

if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

//app.UseHttpsRedirection();
app.UseResponseCompression();
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

app.UseBlazorFrameworkFiles();
app.UseStaticFiles();
app.UseHeaderPropagation();
app.UseRequestLocalization(options => 
    options.AddSupportedCultures("en", "fr")
           .AddSupportedUICultures("en", "fr")
           .SetDefaultCulture("fr"));
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseCors("AllowBlazorClient");
app.MapRazorPages();
app.MapControllers();
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

Console.WriteLine("🚀 SmartNest application starting...");
Console.WriteLine($"🌍 Environment: {app.Environment.EnvironmentName}");
Console.WriteLine($"🔗 Listening on: {string.Join(", ", app.Urls)}");

app.Run();


// Fonction utilitaire pour convertir l'URL PostgreSQL
static string ConvertDatabaseUrl(string databaseUrl)
{
    var uri = new Uri(databaseUrl);
    var userInfo = uri.UserInfo.Split(':');
    
    var connectionString = $"Host={uri.Host};" +
                          $"Port={uri.Port};" +
                          $"Database={uri.AbsolutePath.Trim('/')};" +
                          $"Username={userInfo[0]};" +
                          $"Password={userInfo[1]};" +
                          $"SSL Mode=Require;" +
                          $"Trust Server Certificate=true";
    
    Console.WriteLine($"📝 Connection string configured for host: {uri.Host}");
    return connectionString;
}
