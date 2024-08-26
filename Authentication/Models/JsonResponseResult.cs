using System.Net;
using System.Text.Json.Serialization;

namespace Authentication.Models;

public class JsonResponseResult<T> : JsonResponseResult
{
   public T? Data { get; set; }
   public JsonResponseResult(bool success, string message, HttpStatusCode statusCode, T? data) : base(success, message, statusCode)
   {
      Data = data;
   }

   public JsonResponseResult(bool success, string message, T? data) : base(success, message)
   {
      Data = data;
   }
}

public class JsonResponseResult(
   bool success,
   string message,
   HttpStatusCode statusCode = HttpStatusCode.InternalServerError)
{
   public bool Success { get; init; } = success;

   [JsonIgnore]
   public HttpStatusCode StatusCode { get; set; } = statusCode;

   public string Message { get; set; } = message;
}