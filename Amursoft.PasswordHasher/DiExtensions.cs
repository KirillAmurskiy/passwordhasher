using System;
using Microsoft.Extensions.DependencyInjection;

namespace Amursoft.PasswordHasher
{
    public static class DiExtensions
    {
        public static IServiceCollection AddPbkdf2PasswordHasher(
            this IServiceCollection services,
            Action<Pdkdf2PasswordHasherOptions> configureOptions)
        {
            services.Configure(configureOptions);
             
            return services.AddTransient<IPasswordHasher, Pbkdf2PasswordHasher>();
        }

        public static IServiceCollection AddPbkdf2PasswordHasher(
            this IServiceCollection services)
        {
            return services.AddPbkdf2PasswordHasher(_ => { });
        }
    }
}