namespace Authentication.Models;

public class HttpException(int status, string message, IEnumerable<string> errors, Exception? innerException = null)
    : Exception(message, innerException)
{
    public int Status { get; } = status;
    public IEnumerable<string>? Errors { get; } = errors;

    public HttpException(string message) : this(StatusCodes.Status500InternalServerError, message) { }
    public HttpException(int status, string message) : this(status, message, []){}
}
