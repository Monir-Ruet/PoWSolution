using Authentication.DapperIdentity.Stores;
using Authentication.Data;
using Authentication.Models.DapperIdentity;
using Authentication.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Authentication.Extensions;

public static class IdentityBuilderExtensions
{
    public static IdentityBuilder AddDapperStores(this IdentityBuilder builder, Action<DbProviderOptions>? dbProviderOptionsAction = null) {
        AddStores(builder.Services, builder.UserType, builder.RoleType);
        var options = GetDefaultOptions();
        dbProviderOptionsAction?.Invoke(options);
        builder.Services.AddSingleton(options);
        
        builder.Services.AddScoped<IUserService, UserService>();
        builder.Services.AddScoped<IMailService, MailService>();
        builder.Services.AddScoped<IDatabaseConnection>(_ => new DatabaseConnection(options.ConnectionString!, options.DbSchema));

        return builder;
    }

    private static void AddStores(IServiceCollection services, Type userType, Type? roleType) {
        if (userType != typeof(ApplicationUser)) {
            throw new InvalidOperationException($"{nameof(AddDapperStores)} can only be called with a user that is of type {nameof(ApplicationUser)}.");
        }

        if (roleType != null) {
            if (roleType != typeof(ApplicationRole))
            {
                throw new InvalidOperationException(
                    $"{nameof(AddDapperStores)} can only be called with a role that is of type {nameof(ApplicationRole)}.");
            }
        }
        services.TryAddScoped<IUserStore<ApplicationUser>, UserStore>();
        services.TryAddScoped<IRoleStore<ApplicationRole>, RoleStore>();
    }

    private static DbProviderOptions GetDefaultOptions()
    {
        return new DbProviderOptions();
    }
}