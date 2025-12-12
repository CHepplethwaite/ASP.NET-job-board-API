using API.Middleware;
using backend.Core.Entities;
using backend.Core.Interfaces.Services;
using backend.Infrastructure.Data;
using backend.Infrastructure.Services;
using Core.Interfaces.Services;
using Infrastructure.Security;
using Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

namespace backend.API.Extensions
{
    public static class ServiceExtensions
    {
        public static void AddApplicationServices(this IServiceCollection services, IConfiguration configuration)
        {
            // Database
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(configuration.GetConnectionString("DefaultConnection"),
                sqlServerOptions => sqlServerOptions.MigrationsAssembly("backend")));

            // Identity
            services.AddIdentity<User, Role>(options =>
            {
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 8;

                // User settings
                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters =
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

                // Sign in settings
                options.SignIn.RequireConfirmedEmail = true;
                options.SignIn.RequireConfirmedPhoneNumber = false;

                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            // Configure JWT Settings
            var jwtSettings = configuration.GetSection("JwtSettings");
            services.Configure<JwtSettings>(jwtSettings);

            var key = Encoding.UTF8.GetBytes(jwtSettings["Secret"]);

            // JWT Authentication
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false; // Set to true in production
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings["Issuer"],
                    ValidAudience = jwtSettings["Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ClockSkew = TimeSpan.Zero
                };

                // For Swagger testing
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Add("Token-Expired", "true");
                        }
                        return Task.CompletedTask;
                    },
                    OnMessageReceived = context =>
                    {
                        // Allow token to be passed via query string (for WebSocket connections)
                        var accessToken = context.Request.Query["access_token"];
                        var path = context.HttpContext.Request.Path;
                        if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hub"))
                        {
                            context.Token = accessToken;
                        }
                        return Task.CompletedTask;
                    }
                };
            });

            // External Authentication
            var googleConfig = configuration.GetSection("Authentication:Google");
            if (!string.IsNullOrEmpty(googleConfig["ClientId"]))
            {
                services.AddAuthentication()
                    .AddGoogle(options =>
                    {
                        options.ClientId = googleConfig["ClientId"];
                        options.ClientSecret = googleConfig["ClientSecret"];
                        options.CallbackPath = "/api/auth/external/google-callback";
                        options.Scope.Add("profile");
                        options.Scope.Add("email");
                    });
            }

            var linkedInConfig = configuration.GetSection("Authentication:LinkedIn");
            if (!string.IsNullOrEmpty(linkedInConfig["ClientId"]))
            {
                services.AddAuthentication()
                    .AddLinkedIn(options =>
                    {
                        options.ClientId = linkedInConfig["ClientId"];
                        options.ClientSecret = linkedInConfig["ClientSecret"];
                        options.CallbackPath = "/api/auth/external/linkedin-callback";
                        options.Fields.Add("id");
                        options.Fields.Add("first-name");
                        options.Fields.Add("last-name");
                        options.Fields.Add("email-address");
                        options.Fields.Add("picture-url");
                    });
            }

            // CORS Configuration
            var corsOrigins = configuration.GetSection("CorsOrigins").Get<string[]>()
                ?? new[] { "http://localhost:4200", "https://localhost:4200" };

            services.AddCors(options =>
            {
                options.AddPolicy("AllowAngularApp", policy =>
                {
                    policy.WithOrigins(corsOrigins)
                          .AllowAnyHeader()
                          .AllowAnyMethod()
                          .AllowCredentials()
                          .WithExposedHeaders("Token-Expired", "Content-Disposition");
                });

                // For production
                options.AddPolicy("AllowProduction", policy =>
                {
                    policy.WithOrigins("https://yourdomain.com", "https://www.yourdomain.com")
                          .AllowAnyHeader()
                          .AllowAnyMethod()
                          .AllowCredentials()
                          .SetPreflightMaxAge(TimeSpan.FromHours(1));
                });
            });

            // Swagger Configuration
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "Recruitment Platform API",
                    Version = "v1",
                    Description = "API for Recruitment Platform - Job Seekers, Recruiters, and Companies",
                    Contact = new OpenApiContact
                    {
                        Name = "API Support",
                        Email = "support@recruitmentplatform.com"
                    }
                });

                // Add JWT Authentication to Swagger
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = @"JWT Authorization header using the Bearer scheme. 
                                  Enter 'Bearer' [space] and then your token in the text input below.
                                  Example: 'Bearer 12345abcdef'",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Scheme = "oauth2",
                            Name = "Bearer",
                            In = ParameterLocation.Header
                        },
                        new List<string>()
                    }
                });

                // Include XML comments
                var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                if (File.Exists(xmlPath))
                {
                    c.IncludeXmlComments(xmlPath);
                }
            });

            // Application Services
            services.AddScoped<ITokenService, TokenService>();
            services.AddScoped<IAuthService, AuthService>();
            services.AddScoped<IProfileService, ProfileService>();
            services.AddScoped<IEmailService, EmailService>();
            services.AddScoped<ICurrentUserService, CurrentUserService>();
            services.AddScoped<IFileService, FileService>();

            // File Upload Configuration
            services.Configure<FileUploadSettings>(configuration.GetSection("FileUploadSettings"));

            // HttpContext Accessor
            services.AddHttpContextAccessor();

            // Configure API Behavior
            services.Configure<ApiBehaviorOptions>(options =>
            {
                options.SuppressModelStateInvalidFilter = true;
            });

            // Add Health Checks
            services.AddHealthChecks()
                .AddDbContextCheck<ApplicationDbContext>();
        }

        public static void UseApplicationMiddleware(this IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseMiddleware<ErrorHandlingMiddleware>();

            // Only use JwtMiddleware if you have custom JWT logic
            // app.UseMiddleware<JwtMiddleware>();

            if (env.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI(c =>
                {
                    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Recruitment Platform API v1");
                    c.RoutePrefix = "swagger";
                    c.OAuthClientId("swagger-ui");
                    c.OAuthAppName("Swagger UI");
                    c.OAuthUsePkce();
                });
            }

            // CORS - Use appropriate policy based on environment
            if (env.IsDevelopment())
            {
                app.UseCors("AllowAngularApp");
            }
            else
            {
                app.UseCors("AllowProduction");
            }

            // Static files for uploaded content
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(
                    Path.Combine(Directory.GetCurrentDirectory(), "wwwroot")),
                RequestPath = "/uploads"
            });
        }
    }

    // Add FileUploadSettings class
    public class FileUploadSettings
    {
        public int MaxFileSizeMB { get; set; } = 5;
        public string AllowedExtensions { get; set; } = ".pdf,.doc,.docx,.jpg,.jpeg,.png,.gif";
        public string UploadPath { get; set; } = "uploads";
        public string CvPath { get; set; } = "cv";
        public string ProfilePicturesPath { get; set; } = "profile-pictures";
    }
}