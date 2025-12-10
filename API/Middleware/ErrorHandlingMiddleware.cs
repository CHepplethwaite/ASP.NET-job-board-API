using Core.Exceptions;
using System.Net;
using System.Text.Json;

namespace API.Middleware;

public class ErrorHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ErrorHandlingMiddleware> _logger;
    private readonly IHostEnvironment _env;

    public ErrorHandlingMiddleware(
        RequestDelegate next,
        ILogger<ErrorHandlingMiddleware> logger,
        IHostEnvironment env)
    {
        _next = next;
        _logger = logger;
        _env = env;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unhandled exception occurred");
            await HandleExceptionAsync(context, ex);
        }
    }

    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.ContentType = "application/json";

        var response = new
        {
            type = "https://tools.ietf.org/html/rfc7231#section-6.6.1",
            title = "An error occurred while processing your request.",
            status = HttpStatusCode.InternalServerError,
            detail = _env.IsDevelopment() ? exception.Message : null,
            instance = context.Request.Path,
            traceId = context.TraceIdentifier
        };

        context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

        switch (exception)
        {
            case AuthException authEx:
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                response = new
                {
                    type = "https://tools.ietf.org/html/rfc7235#section-3.1",
                    title = "Authentication error",
                    status = HttpStatusCode.Unauthorized,
                    detail = authEx.Message,
                    instance = context.Request.Path,
                    traceId = context.TraceIdentifier
                };
                break;

            case NotFoundException notFoundEx:
                context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                response = new
                {
                    type = "https://tools.ietf.org/html/rfc7231#section-6.5.4",
                    title = "Resource not found",
                    status = HttpStatusCode.NotFound,
                    detail = notFoundEx.Message,
                    instance = context.Request.Path,
                    traceId = context.TraceIdentifier
                };
                break;

            case ValidationException validationEx:
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                response = new
                {
                    type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                    title = "Validation error",
                    status = HttpStatusCode.BadRequest,
                    detail = "One or more validation errors occurred.",
                    errors = validationEx.Errors,
                    instance = context.Request.Path,
                    traceId = context.TraceIdentifier
                };
                break;

            case UnauthorizedAccessException:
                context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                response = new
                {
                    type = "https://tools.ietf.org/html/rfc7231#section-6.5.3",
                    title = "Access denied",
                    status = HttpStatusCode.Forbidden,
                    detail = "You do not have permission to access this resource.",
                    instance = context.Request.Path,
                    traceId = context.TraceIdentifier
                };
                break;
        }

        var jsonResponse = JsonSerializer.Serialize(response, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        await context.Response.WriteAsync(jsonResponse);
    }
}