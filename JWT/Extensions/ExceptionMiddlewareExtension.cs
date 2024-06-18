using System.Net;
using Microsoft.AspNetCore.Diagnostics;
using Newtonsoft.Json;

namespace JWT.Extensions
{
    public static class ExceptionMiddlewareExtension
    {
        public static void ConfigureExceptionHandler(this IApplicationBuilder appBuilder)
        {
            appBuilder.UseExceptionHandler(appError =>
            {
                appError.Run(async context =>
                {
                    context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    context.Response.ContentType = "application/json";

                    var contextFeature = context.Features.Get<IExceptionHandlerFeature>();
                    if (contextFeature != null)
                    {
                        var errorResponse = new
                        {
                            StatusCode = context.Response.StatusCode,
                            Message = "Internal Server Error.",
                            Detailed = contextFeature.Error.Message
                        };

                        var jsonResponse = JsonConvert.SerializeObject(errorResponse);

                        await context.Response.WriteAsync(jsonResponse);
                    }
                });
            });
        }
    }
}
