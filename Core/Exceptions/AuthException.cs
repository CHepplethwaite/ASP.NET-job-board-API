namespace Core.Exceptions;

public class AuthException : Exception
{
    public AuthException(string message) : base(message) { }

    public AuthException(string message, Exception innerException)
        : base(message, innerException) { }
}

public class NotFoundException : Exception
{
    public NotFoundException(string message) : base(message) { }

    public NotFoundException(string name, object key)
        : base($"Entity \"{name}\" ({key}) was not found.") { }
}

public class ValidationException : Exception
{
    public IDictionary<string, string[]> Errors { get; }

    public ValidationException(IDictionary<string, string[]> errors)
        : base("Validation failed")
    {
        Errors = errors;
    }
}