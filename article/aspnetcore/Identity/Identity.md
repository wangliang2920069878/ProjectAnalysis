|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AspNetRoleManager](#aspnetrolemanager)
* [AspNetUserManager](#aspnetusermanager)
* [DataProtectionTokenProviderOptions](#Ddtaprotectiontokenprovideroptions)
* [DataProtectorTokenProvider](#dataprotectortokenprovider)
* [ExternalLoginInfo](#externallogininfo)
* [IdentityBuilderExtensions](#identitybuilderextensions)
* [IdentityConstants](#identityconstants)
* [IdentityCookiesBuilder](#identitycookiesbuilder)
* [IdentityCookieAuthenticationBuilderExtensions](#identitycookieauthenticationbuilderextensions)
* [IdentityServiceCollectionExtensions](#identityservicecollectionextensions)
* [ISecurityStampValidator](#isecuritystampvalidator)
* [ITwoFactorSecurityStampValidator](#itwofactorsecuritystampValidator)
* [SecurityStampRefreshingPrincipalContext](#securitystamprefreshingprincipalcontext)
* [SecurityStampValidator](#securitystampvalidator)
* [SecurityStampValidatorOptions](#securitystampvalidatoroptions)
* [SignInManager](#signinmanager)
* [TwoFactorSecurityStampValidator](#twofactorsecuritystampValidator)
```
    /// <summary>
    /// 提供用于管理持久性存储中的角色的API。
    /// </summary>
    /// <typeparam name="TRole">封装角色的类型.</typeparam>
    public class AspNetRoleManager<TRole> : RoleManager<TRole>, IDisposable where TRole : class
    {
        private readonly CancellationToken _cancel;

        /// <summary>
        /// Constructs a new instance of <see cref="RoleManager{TRole}"/>.
        /// </summary>
        /// <param name="store">管理将操作的持久性存储.</param>
        /// <param name="roleValidators">角色验证器的集合。</param>
        /// <param name="keyNormalizer">将角色名称标准化为键时使用的标准化器。</param>
        /// <param name="errors">The <see cref="IdentityErrorDescriber"/> 用于提供程序错误消息.</param>
        /// <param name="logger">The logger used to log messages, warnings and errors.</param>
        /// <param name="contextAccessor">用于访问<see cref =“ HttpContext” />的访问器.</param>
        public AspNetRoleManager(IRoleStore<TRole> store,
            IEnumerable<IRoleValidator<TRole>> roleValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            ILogger<RoleManager<TRole>> logger,
            IHttpContextAccessor contextAccessor)
            : base(store, roleValidators, keyNormalizer, errors, logger)
        {
            _cancel = contextAccessor?.HttpContext?.RequestAborted ?? CancellationToken.None;
        }

        /// <summary>
        /// 与当前HttpContext.RequestAborted或CancellationToken.None关联的取消令牌（如果不可用）。
        /// </summary>
        protected override CancellationToken CancellationToken => _cancel;
    }
```
### AspNetUserManager
```
    /// <summary>
    /// 提供用于在持久性存储中管理用户的API。
    /// </summary>
    /// <typeparam name="TUser">封装用户的类型.</typeparam>
    public class AspNetUserManager<TUser> : UserManager<TUser>, IDisposable where TUser : class
    {
        private readonly CancellationToken _cancel;

        /// <summary>
        /// Constructs a new instance of <see cref="AspNetUserManager{TUser}"/>.
        /// </summary>
        /// <param name="store">管理将操作的持久性存储.</param>
        /// <param name="optionsAccessor">用于访问<see cref =“ IdentityOptions” />的访问器。</param>
        /// <param name="passwordHasher">保存密码时要使用的密码哈希实现。</param>
        /// <param name="userValidators"><see cref =“ IUserValidator {TUser}”“ />的集合，用于验证用户。</param>
        /// <param name="passwordValidators"><see cref =“ IPasswordValidator {TUser}” /> />的集合，用于验证密码。</param>
        /// <param name="keyNormalizer"><为用户生成索引键时使用的<see cref =“ ILookupNormalizer” />。</param>
        /// <param name="errors">The <see cref="IdentityErrorDescriber"/> used to provider error messages.</param>
        /// <param name="services"><see cref =“ IServiceProvider” />用于解析服务。</param>
        /// <param name="logger">The logger used to log messages, warnings and errors.</param>
        public AspNetUserManager(IUserStore<TUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<TUser> passwordHasher,
            IEnumerable<IUserValidator<TUser>> userValidators,
            IEnumerable<IPasswordValidator<TUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<TUser>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            _cancel = services?.GetService<IHttpContextAccessor>()?.HttpContext?.RequestAborted ?? CancellationToken.None;
        }

        /// <summary>
        /// The cancellation token associated with the current HttpContext.RequestAborted or CancellationToken.None if unavailable.
        /// </summary>
        protected override CancellationToken CancellationToken => _cancel;
   }
```
### DataProtectionTokenProviderOptions
```
    /// <summary>
    /// 包含<see cref =“ DataProtectorTokenProvider {TUser}” />的选项。
    /// </summary>
    public class DataProtectionTokenProviderOptions
    {
        /// <summary>
        ///获取或设置<see cref =“ DataProtectorTokenProvider {TUser}” /> />的名称。 默认为DataProtectorTokenProvider。
        /// </summary>
        /// <value>
        /// The name of the <see cref="DataProtectorTokenProvider{TUser}"/>.
        /// </value>
        public string Name { get; set; } = "DataProtectorTokenProvider";

        /// <summary>
        ///获取或设置生成的令牌保持有效的时间。 默认为1天。
        /// </summary>
        /// <value>
        /// The amount of time a generated token remains valid.
        /// </value>
        public TimeSpan TokenLifespan { get; set; } = TimeSpan.FromDays(1);
    }
```
### DataProtectorTokenProvider
```
    /// <summary>
    /// 提供身份令牌的保护和验证。
    /// </summary>
    /// <typeparam name="TUser">The type used to represent a user.</typeparam>
    public class DataProtectorTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser> where TUser : class
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DataProtectorTokenProvider{TUser}"/> class.
        /// </summary>
        /// <param name="dataProtectionProvider">系统数据保护提供者.</param>
        /// <param name="options">已配置的<see cref =“ DataProtectionTokenProviderOptions” />.</param>
        /// <param name="logger">The logger used to log messages, warnings and errors.</param>
        public DataProtectorTokenProvider(IDataProtectionProvider dataProtectionProvider,
                                          IOptions<DataProtectionTokenProviderOptions> options,
                                          ILogger<DataProtectorTokenProvider<TUser>> logger)
        {
            if (dataProtectionProvider == null)
            {
                throw new ArgumentNullException(nameof(dataProtectionProvider));
            }

            Options = options?.Value ?? new DataProtectionTokenProviderOptions();

            // Use the Name as the purpose which should usually be distinct from others
            Protector = dataProtectionProvider.CreateProtector(Name ?? "DataProtectorTokenProvider");
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 获取此实例的<see cref =“ DataProtectionTokenProviderOptions” />。
        /// </summary>
        /// <value>
        /// The <see cref="DataProtectionTokenProviderOptions"/> for this instance.
        /// </value>
        protected DataProtectionTokenProviderOptions Options { get; private set; }

        /// <summary>
        ///获取此实例的<see cref =“ IDataProtector” />。
        /// </summary>
        /// <value>
        /// The <see cref="IDataProtector"/> for this instance.
        /// </value>
        protected IDataProtector Protector { get; private set; }

        /// <summary>
        ///获取此实例的名称。
        /// </summary>
        /// <value>
        /// The name of this instance.
        /// </value>
        public string Name { get { return Options.Name; } }

        /// <summary>
        /// 获取<see cref =“ ILogger” />用来记录来自提供者的消息。
        /// </summary>
        /// <value>
        /// The <see cref="ILogger"/> used to log messages from the provider.
        /// </value>
        public ILogger<DataProtectorTokenProvider<TUser>> Logger { get; }

        /// <summary>
        /// 为指定的<paramref name =“ user” />生成一个受保护的令牌，作为异步操作。
        /// </summary>
        /// <param name="purpose">令牌将用于的目的.</param>
        /// <param name="manager"><see cref =“ UserManager {TUser}”“ />从中检索用户属性.</param>
        /// <param name="user">The <typeparamref name="TUser"/> the token will be generated from.</param>
        /// <returns><see cref =“ Task {TResult}” /> />代表生成的令牌。</returns>
        public virtual async Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var ms = new MemoryStream();
            var userId = await manager.GetUserIdAsync(user);
            using (var writer = ms.CreateWriter())
            {
                writer.Write(DateTimeOffset.UtcNow);
                writer.Write(userId);
                writer.Write(purpose ?? "");
                string stamp = null;
                if (manager.SupportsUserSecurityStamp)
                {
                    stamp = await manager.GetSecurityStampAsync(user);
                }
                writer.Write(stamp ?? "");
            }
            var protectedBytes = Protector.Protect(ms.ToArray());
            return Convert.ToBase64String(protectedBytes);
        }

        /// <summary>
        /// 验证指定的<paramref name =“ user” />和<paramref name =“ purpose” />的受保护<paramref name =“ token” />作为异步操作。
        /// </summary>
        /// <param name="purpose">令牌的用途.</param>
        /// <param name="token">验证令牌.</param>
        /// <param name="manager"><see cref =“ UserManager {TUser}”“ />从中检索用户属性.</param>
        /// <param name="user">为该令牌生成的<typeparamref name =“ TUser” />.</param>
        /// <returns>
        /// <see cref =“ Task {TResult}”“ />代表异步验证的结果，
         ///如果令牌有效，则为true，否则为false。
        /// </returns>
        public virtual async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
        {
            try
            {
                var unprotectedData = Protector.Unprotect(Convert.FromBase64String(token));
                var ms = new MemoryStream(unprotectedData);
                using (var reader = ms.CreateReader())
                {
                    var creationTime = reader.ReadDateTimeOffset();
                    var expirationTime = creationTime + Options.TokenLifespan;
                    if (expirationTime < DateTimeOffset.UtcNow)
                    {
                        Logger.InvalidExpirationTime();
                        return false;
                    }

                    var userId = reader.ReadString();
                    var actualUserId = await manager.GetUserIdAsync(user);
                    if (userId != actualUserId)
                    {
                        Logger.UserIdsNotEquals();
                        return false;
                    }

                    var purp = reader.ReadString();
                    if (!string.Equals(purp, purpose))
                    {
                        Logger.PurposeNotEquals(purpose, purp);
                        return false;
                    }

                    var stamp = reader.ReadString();
                    if (reader.PeekChar() != -1)
                    {
                        Logger.UnexpectedEndOfInput();
                        return false;
                    }

                    if (manager.SupportsUserSecurityStamp)
                    {
                        var isEqualsSecurityStamp = stamp == await manager.GetSecurityStampAsync(user);
                        if (!isEqualsSecurityStamp)
                        {
                            Logger.SequrityStampNotEquals();
                        }

                        return isEqualsSecurityStamp;
                    }


                    var stampIsEmpty = stamp == "";
                    if (!stampIsEmpty)
                    {
                        Logger.SecurityStampIsNotEmpty();
                    }

                    return stampIsEmpty;
                }
            }
            // ReSharper disable once EmptyGeneralCatchClause
            catch
            {
                // Do not leak exception
                Logger.UnhandledException();
            }

            return false;
        }

        /// <summary>
        /// 返回一个<see cref =“ bool” />，指示此实例是否生成令牌
         ///可用作异步操作的两因素身份验证令牌。
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> to retrieve user properties from.</param>
        /// <param name="user">The <typeparamref name="TUser"/> the token was generated for.</param>
        /// <returns>
        /// <see cref =“ Task {TResult}”“ />代表异步查询的结果，
         ///如果此实例生成的令牌可以用作“双重身份验证”令牌，则包含true，否则包含false。
        /// </returns>
        /// <remarks>对于<see cref =“ DataProtectorTokenProvider {TUser}” /> />的实例，此方法将始终返回false。</remarks>
        public virtual Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
        {
            return Task.FromResult(false);
        }
    }
```
### ExternalLoginInfo
```
    /// <summary>
    /// 代表用户记录的登录信息，源和外部源主体
    /// </summary>
    public class ExternalLoginInfo : UserLoginInfo
    {
        /// <summary>
        /// 创建<see cref =“ ExternalLoginInfo” />的新实例
        /// </summary>
        /// <param name="principal"><see cref =“ ClaimsPrincipal” />与此登录名相关联.</param>
        /// <param name="loginProvider">与该登录信息关联的提供者.</param>
        /// <param name="providerKey">登录提供者为该用户提供的唯一标识符。</param>
        /// <param name="displayName">登录提供者的显示名称.</param>
        public ExternalLoginInfo(ClaimsPrincipal principal, string loginProvider, string providerKey, 
            string displayName) : base(loginProvider, providerKey, displayName)
        {
            Principal = principal;
        }

        /// <summary>
        /// 获取或设置与此登录关联的<see cref =“ ClaimsPrincipal” />。
        /// </summary>
        /// <value>The <see cref="ClaimsPrincipal"/> associated with this login.</value>
        public ClaimsPrincipal Principal { get; set; }

        /// <summary>
        /// 与该登录名关联的<see cref =“ AuthenticationToken” />。
        /// </summary>
        public IEnumerable<AuthenticationToken> AuthenticationTokens { get; set; }

        /// <summary>
        /// 与该登录名关联的<see cref =“ Authentication.AuthenticationProperties” />。
        /// </summary>
        public AuthenticationProperties AuthenticationProperties { get; set; }
    }
```
### IdentityBuilderExtensions
```
    /// <summary>
    /// 帮助程序功能，用于配置身份服务。
    /// </summary>
    public static class IdentityBuilderExtensions
    {
        /// <summary>
        /// 添加用于生成重置密码令牌，更改电子邮件的默认令牌提供程序
         ///并更改电话号码操作，以及用于生成两个因素的身份验证令牌。
        /// </summary>
        /// <param name="builder">The current <see cref="IdentityBuilder"/> instance.</param>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public static IdentityBuilder AddDefaultTokenProviders(this IdentityBuilder builder)
        {
            var userType = builder.UserType;
            var dataProtectionProviderType = typeof(DataProtectorTokenProvider<>).MakeGenericType(userType);
            var phoneNumberProviderType = typeof(PhoneNumberTokenProvider<>).MakeGenericType(userType);
            var emailTokenProviderType = typeof(EmailTokenProvider<>).MakeGenericType(userType);
            var authenticatorProviderType = typeof(AuthenticatorTokenProvider<>).MakeGenericType(userType);
            return builder.AddTokenProvider(TokenOptions.DefaultProvider, dataProtectionProviderType)
                .AddTokenProvider(TokenOptions.DefaultEmailProvider, emailTokenProviderType)
                .AddTokenProvider(TokenOptions.DefaultPhoneProvider, phoneNumberProviderType)
                .AddTokenProvider(TokenOptions.DefaultAuthenticatorProvider, authenticatorProviderType);
        }

        private static void AddSignInManagerDeps(this IdentityBuilder builder)
        {
            builder.Services.AddHttpContextAccessor();
            builder.Services.AddScoped(typeof(ISecurityStampValidator), typeof(SecurityStampValidator<>).MakeGenericType(builder.UserType));
            builder.Services.AddScoped(typeof(ITwoFactorSecurityStampValidator), typeof(TwoFactorSecurityStampValidator<>).MakeGenericType(builder.UserType));
        }

        /// <summary>
        ///为<seealso cref =“ IdentityBuilder.UserType” />添加<see cref =“ SignInManager {TUser}”“ />。
        /// </summary>
        /// <param name="builder">The current <see cref="IdentityBuilder"/> instance.</param>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public static IdentityBuilder AddSignInManager(this IdentityBuilder builder)
        {
            builder.AddSignInManagerDeps();
            var managerType = typeof(SignInManager<>).MakeGenericType(builder.UserType);
            builder.Services.AddScoped(managerType);
            return builder;
        }

        /// <summary>
        ///为<seealso cref =“ IdentityBuilder.UserType” />添加<see cref =“ SignInManager {TUser}”“ />。
        /// </summary>
        /// <typeparam name="TSignInManager">要添加的登录管理器的类型。</typeparam>
        /// <param name="builder">The current <see cref="IdentityBuilder"/> instance.</param>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public static IdentityBuilder AddSignInManager<TSignInManager>(this IdentityBuilder builder) where TSignInManager : class
        {
            builder.AddSignInManagerDeps();
            var managerType = typeof(SignInManager<>).MakeGenericType(builder.UserType);
            var customType = typeof(TSignInManager);
            if (!managerType.GetTypeInfo().IsAssignableFrom(customType.GetTypeInfo()))
            {
                throw new InvalidOperationException(Resources.FormatInvalidManagerType(customType.Name, "SignInManager", builder.UserType.Name));
            }
            if (managerType != customType)
            {
                builder.Services.AddScoped(typeof(TSignInManager), services => services.GetRequiredService(managerType));
            }
            builder.Services.AddScoped(managerType, typeof(TSignInManager));
            return builder;
        }
    }
```
### IdentityConstants
```
    /// <summary>
    ///表示可用于配置身份系统使用的cookie中间件的所有选项。
    /// </summary>
    public class IdentityConstants
    {
        private static readonly string CookiePrefix = "Identity";
        /// <summary>
        /// 用于标识应用程序身份验证cookie的方案。
        /// </summary>
        public static readonly string ApplicationScheme = CookiePrefix + ".Application";

        /// <summary>
        /// 用于标识外部身份验证cookie的方案。
        /// </summary>
        public static readonly string ExternalScheme = CookiePrefix + ".External";

        /// <summary>
        /// 用于标识“两因素”身份验证Cookie的方案，用于保存“记住我”状态。
        /// </summary>
        public static readonly string TwoFactorRememberMeScheme = CookiePrefix + ".TwoFactorRememberMe";

        /// <summary>
        /// 该方案用于为往返用户身份标识“两因素”身份验证cookie。
        /// </summary>
        public static readonly string TwoFactorUserIdScheme = CookiePrefix + ".TwoFactorUserId";
    }
```
### IdentityCookiesBuilder
```
    /// <summary>
    /// 用于配置身份cookie选项。
    /// </summary>
    public class IdentityCookiesBuilder
    {
        /// <summary>
        ///用于配置应用程序cookie。
        /// </summary>
        public OptionsBuilder<CookieAuthenticationOptions> ApplicationCookie { get; set; }

        /// <summary>
        /// 用于配置外部cookie。
        /// </summary>
        public OptionsBuilder<CookieAuthenticationOptions> ExternalCookie { get; set; }

        /// <summary>
        ///用于配置两个因素的记住我的cookie。
        /// </summary>
        public OptionsBuilder<CookieAuthenticationOptions> TwoFactorRememberMeCookie { get; set; }

        /// <summary>
        ///用于配置两因素用户ID cookie。
        /// </summary>
        public OptionsBuilder<CookieAuthenticationOptions> TwoFactorUserIdCookie { get; set; }
    }
```
### IdentityCookieAuthenticationBuilderExtensions
```
    /// <summary>
    /// 帮助程序功能，用于配置身份服务。
    /// </summary>
    public static class IdentityCookieAuthenticationBuilderExtensions
    {
        /// <summary>
        /// 添加cookie身份验证。
        /// </summary>
        /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
        /// <returns>The <see cref="IdentityCookiesBuilder"/> which can be used to configure the identity cookies.</returns>
        public static IdentityCookiesBuilder AddIdentityCookies(this AuthenticationBuilder builder)
            => builder.AddIdentityCookies(o => { });

        /// <summary>
        /// 添加登录管理器所需的cookie身份验证。
        /// </summary>
        /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
        /// <param name="configureCookies">Action used to configure the cookies.</param>
        /// <returns>The <see cref="IdentityCookiesBuilder"/> which can be used to configure the identity cookies.</returns>
        public static IdentityCookiesBuilder AddIdentityCookies(this AuthenticationBuilder builder, Action<IdentityCookiesBuilder> configureCookies)
        {
            var cookieBuilder = new IdentityCookiesBuilder();
            cookieBuilder.ApplicationCookie = builder.AddApplicationCookie();
            cookieBuilder.ExternalCookie = builder.AddExternalCookie();
            cookieBuilder.TwoFactorRememberMeCookie = builder.AddTwoFactorRememberMeCookie();
            cookieBuilder.TwoFactorUserIdCookie = builder.AddTwoFactorUserIdCookie();
            configureCookies?.Invoke(cookieBuilder);
            return cookieBuilder;
        }

        /// <summary>
        /// 添加身份应用程序cookie。
        /// </summary>
        /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
        /// <returns>The <see cref="OptionsBuilder{TOptions}"/> which can be used to configure the cookie authentication.</returns>
        public static OptionsBuilder<CookieAuthenticationOptions> AddApplicationCookie(this AuthenticationBuilder builder)
        {
            builder.AddCookie(IdentityConstants.ApplicationScheme, o =>
            {
                o.LoginPath = new PathString("/Account/Login");
                o.Events = new CookieAuthenticationEvents
                {
                    OnValidatePrincipal = SecurityStampValidator.ValidatePrincipalAsync
                };
            });
            return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.ApplicationScheme);
        }

        /// <summary>
        /// 添加用于外部登录的身份cookie。
        /// </summary>
        /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
        /// <returns>The <see cref="OptionsBuilder{TOptions}"/> which can be used to configure the cookie authentication.</returns>
        public static OptionsBuilder<CookieAuthenticationOptions> AddExternalCookie(this AuthenticationBuilder builder)
        {
            builder.AddCookie(IdentityConstants.ExternalScheme, o =>
            {
                o.Cookie.Name = IdentityConstants.ExternalScheme;
                o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            });
            return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.ExternalScheme);
        }

        /// <summary>
        /// 添加用于两个因素的身份cookie记住我。
        /// </summary>
        /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
        /// <returns>The <see cref="OptionsBuilder{TOptions}"/> which can be used to configure the cookie authentication.</returns>
        public static OptionsBuilder<CookieAuthenticationOptions> AddTwoFactorRememberMeCookie(this AuthenticationBuilder builder)
        {
            builder.AddCookie(IdentityConstants.TwoFactorRememberMeScheme, o => o.Cookie.Name = IdentityConstants.TwoFactorRememberMeScheme);
            return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.TwoFactorRememberMeScheme);
        }

        /// <summary>
        /// 添加用于两个因子登录的身份cookie。
        /// </summary>
        /// <param name="builder">The current <see cref="AuthenticationBuilder"/> instance.</param>
        /// <returns>The <see cref="OptionsBuilder{TOptions}"/> which can be used to configure the cookie authentication.</returns>
        public static OptionsBuilder<CookieAuthenticationOptions> AddTwoFactorUserIdCookie(this AuthenticationBuilder builder)
        {
            builder.AddCookie(IdentityConstants.TwoFactorUserIdScheme, o =>
            {
                o.Cookie.Name = IdentityConstants.TwoFactorUserIdScheme;
                o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            });
            return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.TwoFactorUserIdScheme);
        }
    }
```
### IdentityServiceCollectionExtensions
```
    /// <summary>
    ///包含对<see cref =“ IServiceCollection” />的扩展方法，用于配置身份服务。
    /// </summary>
    public static class IdentityServiceCollectionExtensions
    {
        /// <summary>
        /// 为指定的用户和角色类型添加默认的身份系统配置。
        /// </summary>
        /// <typeparam name="TUser">代表系统中用户的类型.</typeparam>
        /// <typeparam name="TRole">表示系统中角色的类型.</typeparam>
        /// <param name="services">应用程序中可用的服务.</param>
        /// <returns>An <see cref="IdentityBuilder"/> for creating and configuring the identity system.</returns>
        public static IdentityBuilder AddIdentity<TUser, TRole>(
            this IServiceCollection services)
            where TUser : class
            where TRole : class
            => services.AddIdentity<TUser, TRole>(setupAction: null);

        /// <summary>
        /// Adds and configures the identity system for the specified User and Role types.
        /// </summary>
        /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
        /// <typeparam name="TRole">The type representing a Role in the system.</typeparam>
        /// <param name="services">The services available in the application.</param>
        /// <param name="setupAction">配置<see cref =“ IdentityOptions” />的操作.</param>
        /// <returns>An <see cref="IdentityBuilder"/> for creating and configuring the identity system.</returns>
        public static IdentityBuilder AddIdentity<TUser, TRole>(
            this IServiceCollection services,
            Action<IdentityOptions> setupAction)
            where TUser : class
            where TRole : class
        {
            // Services used by identity
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
                options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
                options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            })
            .AddCookie(IdentityConstants.ApplicationScheme, o =>
            {
                o.LoginPath = new PathString("/Account/Login");
                o.Events = new CookieAuthenticationEvents
                {
                    OnValidatePrincipal = SecurityStampValidator.ValidatePrincipalAsync
                };
            })
            .AddCookie(IdentityConstants.ExternalScheme, o =>
            {
                o.Cookie.Name = IdentityConstants.ExternalScheme;
                o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            })
            .AddCookie(IdentityConstants.TwoFactorRememberMeScheme, o =>
            {
                o.Cookie.Name = IdentityConstants.TwoFactorRememberMeScheme;
                o.Events = new CookieAuthenticationEvents
                {
                    OnValidatePrincipal = SecurityStampValidator.ValidateAsync<ITwoFactorSecurityStampValidator>
                };
            })
            .AddCookie(IdentityConstants.TwoFactorUserIdScheme, o =>
            {
                o.Cookie.Name = IdentityConstants.TwoFactorUserIdScheme;
                o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            });

            // Hosting doesn't add IHttpContextAccessor by default
            services.AddHttpContextAccessor();
            // Identity services
            services.TryAddScoped<IUserValidator<TUser>, UserValidator<TUser>>();
            services.TryAddScoped<IPasswordValidator<TUser>, PasswordValidator<TUser>>();
            services.TryAddScoped<IPasswordHasher<TUser>, PasswordHasher<TUser>>();
            services.TryAddScoped<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            services.TryAddScoped<IRoleValidator<TRole>, RoleValidator<TRole>>();
            // No interface for the error describer so we can add errors without rev'ing the interface
            services.TryAddScoped<IdentityErrorDescriber>();
            services.TryAddScoped<ISecurityStampValidator, SecurityStampValidator<TUser>>();
            services.TryAddScoped<ITwoFactorSecurityStampValidator, TwoFactorSecurityStampValidator<TUser>>();
            services.TryAddScoped<IUserClaimsPrincipalFactory<TUser>, UserClaimsPrincipalFactory<TUser, TRole>>();
            services.TryAddScoped<IUserConfirmation<TUser>, DefaultUserConfirmation<TUser>>();
            services.TryAddScoped<UserManager<TUser>>();
            services.TryAddScoped<SignInManager<TUser>>();
            services.TryAddScoped<RoleManager<TRole>>();

            if (setupAction != null)
            {
                services.Configure(setupAction);
            }

            return new IdentityBuilder(typeof(TUser), typeof(TRole), services);
        }

        /// <summary>
        /// 配置应用程序cookie。
        /// </summary>
        /// <param name="services">The services available in the application.</param>
        /// <param name="configure">An action to configure the <see cref="CookieAuthenticationOptions"/>.</param>
        /// <returns>The services.</returns>
        public static IServiceCollection ConfigureApplicationCookie(this IServiceCollection services, Action<CookieAuthenticationOptions> configure)
            => services.Configure(IdentityConstants.ApplicationScheme, configure);

        /// <summary>
        ///配置外部cookie。
        /// </summary>
        /// <param name="services">The services available in the application.</param>
        /// <param name="configure">An action to configure the <see cref="CookieAuthenticationOptions"/>.</param>
        /// <returns>The services.</returns>
        public static IServiceCollection ConfigureExternalCookie(this IServiceCollection services, Action<CookieAuthenticationOptions> configure)
            => services.Configure(IdentityConstants.ExternalScheme, configure);
    }
```
### ISecurityStampValidator
```
    /// <summary>
    /// 提供一种抽象，用于验证传入身份的安全标记，并重新生成或拒绝
     ///基于验证结果的身份。
    /// </summary>
    public interface ISecurityStampValidator
    {
        /// <summary>
        ///将身份安全戳验证为异步操作，如果验证成功，则重建身份，否则拒绝
         /// 身份。
        /// </summary>
        /// <param name="context">The context containing the <see cref="System.Security.Claims.ClaimsPrincipal"/>
        /// and <see cref="AuthenticationProperties"/> to validate.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous validation operation.</returns>
        Task ValidateAsync(CookieValidatePrincipalContext context);
    }
```
### ITwoFactorSecurityStampValidator
```
    /// <summary>
    /// 用于验证记住客户端cookie安全性戳的两个因素。
    /// </summary>
    public interface ITwoFactorSecurityStampValidator : ISecurityStampValidator
    { }
```
### SecurityStampRefreshingPrincipalContext
```
    /// <summary>
    /// 用于在SecurityStamp验证事件期间传递信息。
    /// </summary>
    public class SecurityStampRefreshingPrincipalContext
    {
        /// <summary>
        /// 当前cookie中包含的主体。
        /// </summary>
        public ClaimsPrincipal CurrentPrincipal { get; set; }

        /// <summary>
        /// 新的主体应替代当前的主体。
        /// </summary>
        public ClaimsPrincipal NewPrincipal { get; set; }
    }
```
### securitystampvalidator
```
    /// <summary>
    /// 提供安全图章验证功能的默认实现。
    /// </summary>
    /// <typeparam name="TUser">封装用户的类型.</typeparam>
    public class SecurityStampValidator<TUser> : ISecurityStampValidator where TUser : class
    {
        /// <summary>
        /// Creates a new instance of <see cref="SecurityStampValidator{TUser}"/>.
        /// </summary>
        /// <param name="options">用于访问<see cref =“ IdentityOptions” />.</param>
        /// <param name="signInManager">The <see cref="SignInManager{TUser}"/>.</param>
        /// <param name="clock">The system clock.</param>
        /// <param name="logger">The logger.</param>
        public SecurityStampValidator(IOptions<SecurityStampValidatorOptions> options, SignInManager<TUser> signInManager, ISystemClock clock, ILoggerFactory logger)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            if (signInManager == null)
            {
                throw new ArgumentNullException(nameof(signInManager));
            }
            SignInManager = signInManager;
            Options = options.Value;
            Clock = clock;
            Logger = logger.CreateLogger(this.GetType().FullName);
        }

        /// <summary>
        /// The SignInManager.
        /// </summary>
        public SignInManager<TUser> SignInManager { get; }

        /// <summary>
        /// The <see cref="SecurityStampValidatorOptions"/>.
        /// </summary>
        public SecurityStampValidatorOptions Options { get; }

        /// <summary>
        /// The <see cref="ISystemClock"/>.
        /// </summary>
        public ISystemClock Clock { get; }

        /// <summary>
        /// Gets the <see cref="ILogger"/> used to log messages.
        /// </summary>
        /// <value>
        /// The <see cref="ILogger"/> used to log messages.
        /// </value>
        public ILogger Logger { get; set; }
        
        /// <summary>
        /// 验证安全标记后调用。
        /// </summary>
        /// <param name="user">已验证的用户。</param>
        /// <param name="context"><see cref =“ CookieValidatePrincipalContext” />.</param>
        /// <returns>A task.</returns>
        protected virtual async Task SecurityStampVerified(TUser user, CookieValidatePrincipalContext context)
        {
            var newPrincipal = await SignInManager.CreateUserPrincipalAsync(user);

            if (Options.OnRefreshingPrincipal != null)
            {
                var replaceContext = new SecurityStampRefreshingPrincipalContext
                {
                    CurrentPrincipal = context.Principal,
                    NewPrincipal = newPrincipal
                };

                // 注意：允许使用空主体，并导致身份验证失败。
                await Options.OnRefreshingPrincipal(replaceContext);
                newPrincipal = replaceContext.NewPrincipal;
            }

            // 点评：请注意，我们丢失了登录身份验证方法
            context.ReplacePrincipal(newPrincipal);
            context.ShouldRenew = true;
        }

        /// <summary>
        /// 验证主体的安全标记，如果成功，则返回匹配的用户
        /// </summary>
        /// <param name="principal">The principal to verify.</param>
        /// <returns>经过验证的用户；如果验证失败，则为null。</returns>
        protected virtual Task<TUser> VerifySecurityStamp(ClaimsPrincipal principal)
            => SignInManager.ValidateSecurityStampAsync(principal);

        /// <summary>
        ///将身份安全戳验证为异步操作，如果验证成功，则重建身份，否则拒绝
         /// 身份。
        /// </summary>
        /// <param name="context">The context containing the <see cref="System.Security.Claims.ClaimsPrincipal"/>
        /// and <see cref="AuthenticationProperties"/> to validate.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous validation operation.</returns>
        public virtual async Task ValidateAsync(CookieValidatePrincipalContext context)
        {
            var currentUtc = DateTimeOffset.UtcNow;
            if (context.Options != null && Clock != null)
            {
                currentUtc = Clock.UtcNow;
            }
            var issuedUtc = context.Properties.IssuedUtc;

            // Only validate if enough time has elapsed
            var validate = (issuedUtc == null);
            if (issuedUtc != null)
            {
                var timeElapsed = currentUtc.Subtract(issuedUtc.Value);
                validate = timeElapsed > Options.ValidationInterval;
            }
            if (validate)
            {
                var user = await VerifySecurityStamp(context.Principal); 
                if (user != null)
                {
                    await SecurityStampVerified(user, context);
                }
                else
                {
                    Logger.LogDebug(0, "Security stamp validation failed, rejecting cookie.");
                    context.RejectPrincipal();
                    await SignInManager.SignOutAsync();
                }
            }
        }
    }

        /// <summary>
    /// 静态帮助程序类，用于配置CookieAuthenticationNotifications以针对用户的安全性验证Cookie
     /// 邮票。
    /// </summary>
    public static class SecurityStampValidator
    {
        /// <summary>
        /// 根据用户存储的安全性戳验证主体。
        /// </summary>
        /// <param name="context">The context containing the <see cref="System.Security.Claims.ClaimsPrincipal"/>
        /// and <see cref="AuthenticationProperties"/> to validate.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous validation operation.</returns>
        public static Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
            => ValidateAsync<ISecurityStampValidator>(context);

        /// <summary>
        /// 用于验证<see cref =“ IdentityConstants.TwoFactorUserIdScheme” />和
         /// <参见cref =“ IdentityConstants.TwoFactorRememberMeScheme” />针对用户的Cookie
         ///存储的安全标记。
        /// </summary>
        /// <param name="context">The context containing the <see cref="System.Security.Claims.ClaimsPrincipal"/>
        /// and <see cref="AuthenticationProperties"/> to validate.</param>
        /// <returns></returns>

        public static Task ValidateAsync<TValidator>(CookieValidatePrincipalContext context) where TValidator : ISecurityStampValidator
        {
            if (context.HttpContext.RequestServices == null)
            {
                throw new InvalidOperationException("RequestServices is null.");
            }

            var validator = context.HttpContext.RequestServices.GetRequiredService<TValidator>();
            return validator.ValidateAsync(context);
        }
    }
```
### SecurityStampValidatorOptions
```
   /// <summary>
    /// <see cref =“ ISecurityStampValidator” />的选项。
    /// </summary>
    public class SecurityStampValidatorOptions
    {
        /// <summary>
        ///获取或设置<see cref =“ TimeSpan” />，之后重新验证安全标记。 默认为30分钟。
        /// </summary>
        /// <value>
        /// The <see cref="TimeSpan"/> after which security stamps are re-validated.
        /// </value>
        public TimeSpan ValidationInterval { get; set; } = TimeSpan.FromMinutes(30);

        /// <summary>
        /// 当默认安全戳验证器替换cookie中用户的ClaimsPrincipal时调用。
        /// </summary>
        public Func<SecurityStampRefreshingPrincipalContext, Task> OnRefreshingPrincipal { get; set; }
    }
```
### SignInManager
```
    /// <summary>
    /// 提供用于用户登录的API。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public class SignInManager<TUser> where TUser : class
    {
        private const string LoginProviderKey = "LoginProvider";
        private const string XsrfKey = "XsrfId";

        /// <summary>
        /// Creates a new instance of <see cref="SignInManager{TUser}"/>.
        /// </summary>
        /// <param name="userManager">An instance of <see cref="UserManager"/> used to retrieve users from and persist users.</param>
        /// <param name="contextAccessor">The accessor used to access the <see cref="HttpContext"/>.</param>
        /// <param name="claimsFactory">The factory to use to create claims principals for a user.</param>
        /// <param name="optionsAccessor">The accessor used to access the <see cref="IdentityOptions"/>.</param>
        /// <param name="logger">The logger used to log messages, warnings and errors.</param>
        /// <param name="schemes">使用的方案提供者枚举身份验证方案。</param>
        /// <param name="confirmation"><see cref =“ IUserConfirmation {TUser}” /> />用于检查是否确认了用户帐户。</param>
        public SignInManager(UserManager<TUser> userManager,
            IHttpContextAccessor contextAccessor,
            IUserClaimsPrincipalFactory<TUser> claimsFactory,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<TUser>> logger,
            IAuthenticationSchemeProvider schemes,
            IUserConfirmation<TUser> confirmation)
        {
            if (userManager == null)
            {
                throw new ArgumentNullException(nameof(userManager));
            }
            if (contextAccessor == null)
            {
                throw new ArgumentNullException(nameof(contextAccessor));
            }
            if (claimsFactory == null)
            {
                throw new ArgumentNullException(nameof(claimsFactory));
            }

            UserManager = userManager;
            _contextAccessor = contextAccessor;
            ClaimsFactory = claimsFactory;
            Options = optionsAccessor?.Value ?? new IdentityOptions();
            Logger = logger;
            _schemes = schemes;
            _confirmation = confirmation;
        }

        private readonly IHttpContextAccessor _contextAccessor;
        private HttpContext _context;
        private IAuthenticationSchemeProvider _schemes;
        private IUserConfirmation<TUser> _confirmation;

        /// <summary>
        /// Gets the <see cref="ILogger"/> used to log messages from the manager.
        /// </summary>
        /// <value>
        /// The <see cref="ILogger"/> used to log messages from the manager.
        /// </value>
        public virtual ILogger Logger { get; set; }

        /// <summary>
        /// The <see cref="UserManager{TUser}"/> used.
        /// </summary>
        public UserManager<TUser> UserManager { get; set; }

        /// <summary>
        /// The <see cref="IUserClaimsPrincipalFactory{TUser}"/> used.
        /// </summary>
        public IUserClaimsPrincipalFactory<TUser> ClaimsFactory { get; set; }

        /// <summary>
        /// The <see cref="IdentityOptions"/> used.
        /// </summary>
        public IdentityOptions Options { get; set; }

        /// <summary>
        /// The <see cref="HttpContext"/> used.
        /// </summary>
        public HttpContext Context
        {
            get
            {
                var context = _context ?? _contextAccessor?.HttpContext;
                if (context == null)
                {
                    throw new InvalidOperationException("HttpContext must not be null.");
                }
                return context;
            }
            set
            {
                _context = value;
            }
        }

        /// <summary>
        /// 为指定的<paramref name =“ user” />创建一个<see cref =“ ClaimsPrincipal” />，作为异步操作。
        /// </summary>
        /// <param name="user">The user to create a <see cref="ClaimsPrincipal"/> for.</param>
        /// <returns>The task object representing the asynchronous operation, containing the ClaimsPrincipal for the specified user.</returns>
        public virtual async Task<ClaimsPrincipal> CreateUserPrincipalAsync(TUser user) => await ClaimsFactory.CreateAsync(user);

        /// <summary>
        /// 如果委托人具有与应用程序cookie身份的身份，则返回true
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> instance.</param>
        /// <returns>True if the user is logged in with identity.</returns>
        public virtual bool IsSignedIn(ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }
            return principal?.Identities != null &&
                principal.Identities.Any(i => i.AuthenticationType == IdentityConstants.ApplicationScheme);
        }

        /// <summary>
        /// 返回一个标志，指示指定的用户是否可以登录。
        /// </summary>
        /// <param name="user">The user whose sign-in status should be returned.</param>
        /// <returns>
        /// The task object representing the asynchronous operation, containing a flag that is true
        /// if the specified user can sign-in, otherwise false.
        /// </returns>
        public virtual async Task<bool> CanSignInAsync(TUser user)
        {
            if (Options.SignIn.RequireConfirmedEmail && !(await UserManager.IsEmailConfirmedAsync(user)))
            {
                Logger.LogWarning(0, "User {userId} cannot sign in without a confirmed email.", await UserManager.GetUserIdAsync(user));
                return false;
            }
            if (Options.SignIn.RequireConfirmedPhoneNumber && !(await UserManager.IsPhoneNumberConfirmedAsync(user)))
            {
                Logger.LogWarning(1, "User {userId} cannot sign in without a confirmed phone number.", await UserManager.GetUserIdAsync(user));
                return false;
            }
            if (Options.SignIn.RequireConfirmedAccount && !(await _confirmation.IsConfirmedAsync(UserManager, user)))
            {
                Logger.LogWarning(4, "User {userId} cannot sign in without a confirmed account.", await UserManager.GetUserIdAsync(user));
                return false;
            }
            return true;
        }

        /// <summary>
        /// 重新生成用户的应用程序cookie，同时保留现有的
         ///作为异步操作的AuthenticationProperties（如RememberMe）。
        /// </summary>
        /// <param name="user">The user whose sign-in cookie should be refreshed.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual async Task RefreshSignInAsync(TUser user)
        {
            var auth = await Context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            var claims = new List<Claim>();
            var authenticationMethod = auth?.Principal?.FindFirst(ClaimTypes.AuthenticationMethod);
            if (authenticationMethod != null)
            {
                claims.Add(authenticationMethod);
            }
            var amr = auth?.Principal?.FindFirst("amr");
            if (amr != null)
            {
                claims.Add(amr);
            }

            await SignInWithClaimsAsync(user, auth?.Properties, claims);
        }

        /// <summary>
        /// 登录指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="user">The user to sign-in.</param>
        /// <param name="isPersistent">指示登录cookie在浏览器关闭后是否应保留的标志。</param>
        /// <param name="authenticationMethod">用于认证用户的方法的名称.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual Task SignInAsync(TUser user, bool isPersistent, string authenticationMethod = null)
            => SignInAsync(user, new AuthenticationProperties { IsPersistent = isPersistent }, authenticationMethod);

        /// <summary>
        /// 登录指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="user">The user to sign-in.</param>
        /// <param name="authenticationProperties">应用于登录和身份验证Cookie的属性。</param>
        /// <param name="authenticationMethod">Name of the method used to authenticate the user.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual Task SignInAsync(TUser user, AuthenticationProperties authenticationProperties, string authenticationMethod = null)
        {
            var additionalClaims = new List<Claim>();
            if (authenticationMethod != null)
            {
                additionalClaims.Add(new Claim(ClaimTypes.AuthenticationMethod, authenticationMethod));
            }
            return SignInWithClaimsAsync(user, authenticationProperties, additionalClaims);
        }

        /// <summary>
        /// Signs in the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to sign-in.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="additionalClaims">将存储在cookie中的其他声明。</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual Task SignInWithClaimsAsync(TUser user, bool isPersistent, IEnumerable<Claim> additionalClaims)
            => SignInWithClaimsAsync(user, new AuthenticationProperties { IsPersistent = isPersistent }, additionalClaims);

        /// <summary>
        /// Signs in the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to sign-in.</param>
        /// <param name="authenticationProperties">Properties applied to the login and authentication cookie.</param>
        /// <param name="additionalClaims">Additional claims that will be stored in the cookie.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual async Task SignInWithClaimsAsync(TUser user, AuthenticationProperties authenticationProperties, IEnumerable<Claim> additionalClaims)
        {
            var userPrincipal = await CreateUserPrincipalAsync(user);
            foreach (var claim in additionalClaims)
            {
                userPrincipal.Identities.First().AddClaim(claim);
            }
            await Context.SignInAsync(IdentityConstants.ApplicationScheme,
                userPrincipal,
                authenticationProperties ?? new AuthenticationProperties());
        }

        /// <summary>
        /// 将当前用户退出应用程序。
        /// </summary>
        public virtual async Task SignOutAsync()
        {
            await Context.SignOutAsync(IdentityConstants.ApplicationScheme);
            await Context.SignOutAsync(IdentityConstants.ExternalScheme);
            await Context.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);
        }

        /// <summary>
        /// 针对指定的<paramref name =“ principal” />验证安全标记
         ///当前用户的持久标记，作为异步操作。
        /// </summary>
        /// <param name="principal">The principal whose stamp should be validated.</param>
        /// <returns>The task object representing the asynchronous operation. The task will contain the <typeparamref name="TUser"/>
        /// 如果图章与持久值匹配，则它将返回false.</returns>
        public virtual async Task<TUser> ValidateSecurityStampAsync(ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                return null;
            }
            var user = await UserManager.GetUserAsync(principal);
            if (await ValidateSecurityStampAsync(user, principal.FindFirstValue(Options.ClaimsIdentity.SecurityStampClaimType)))
            {
                return user;
            }
            Logger.LogDebug(4, "Failed to validate a security stamp.");
            return null;
        }

        /// <summary>
        ///从以下其中一项验证指定的<paramref name =“ principal” />的安全性戳：
         ///针对以下两个因素的主体（记住客户端或用户ID）
         ///当前用户的持久标记，作为异步操作。
        /// </summary>
        /// <param name="principal">The principal whose stamp should be validated.</param>
        /// <returns>The task object representing the asynchronous operation. The task will contain the <typeparamref name="TUser"/>
        /// if the stamp matches the persisted value, otherwise it will return false.</returns>
        public virtual async Task<TUser> ValidateTwoFactorSecurityStampAsync(ClaimsPrincipal principal)
        {
            if (principal == null || principal.Identity?.Name == null)
            {
                return null;
            }
            var user = await UserManager.FindByIdAsync(principal.Identity.Name);
            if (await ValidateSecurityStampAsync(user, principal.FindFirstValue(Options.ClaimsIdentity.SecurityStampClaimType)))
            {
                return user;
            }
            Logger.LogDebug(5, "Failed to validate a security stamp.");
            return null;
        }

        /// <summary>
        /// 验证指定的<paramref name =“ user” />的安全性戳。 永远会返回false
         ///如果userManager不支持安全标记。
        /// </summary>
        /// <param name="user">The user whose stamp should be validated.</param>
        /// <param name="securityStamp">The expected security stamp value.</param>
        /// <returns>True if the stamp matches the persisted value, otherwise it will return false.</returns>
        public virtual async Task<bool> ValidateSecurityStampAsync(TUser user, string securityStamp)
            => user != null &&
            // Only validate the security stamp if the store supports it
            (!UserManager.SupportsUserSecurityStamp || securityStamp == await UserManager.GetSecurityStampAsync(user));

        /// <summary>
        ///尝试登录指定的<paramref name =“ user” />和<paramref name =“ password” />组合
         ///作为异步操作。
        /// </summary>
        /// <param name="user">The user to sign in.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="lockoutOnFailure">指示登录失败时是否应锁定用户帐户的标志。</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public virtual async Task<SignInResult> PasswordSignInAsync(TUser user, string password,
            bool isPersistent, bool lockoutOnFailure)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var attempt = await CheckPasswordSignInAsync(user, password, lockoutOnFailure);
            return attempt.Succeeded
                ? await SignInOrTwoFactorAsync(user, isPersistent)
                : attempt;
        }

        /// <summary>
        /// 尝试登录指定的<paramref name =“ userName” />和<paramref name =“ password” />组合
         ///作为异步操作。
        /// </summary>
        /// <param name="userName">The user name to sign in.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public virtual async Task<SignInResult> PasswordSignInAsync(string userName, string password,
            bool isPersistent, bool lockoutOnFailure)
        {
            var user = await UserManager.FindByNameAsync(userName);
            if (user == null)
            {
                return SignInResult.Failed;
            }

            return await PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
        }

        /// <summary>
        /// 尝试为用户登录密码。
        /// </summary>
        /// <param name="user">The user to sign in.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        /// <returns></returns>
        public virtual async Task<SignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var error = await PreSignInCheck(user);
            if (error != null)
            {
                return error;
            }

            if (await UserManager.CheckPasswordAsync(user, password))
            {
                var alwaysLockout = AppContext.TryGetSwitch("Microsoft.AspNetCore.Identity.CheckPasswordSignInAlwaysResetLockoutOnSuccess", out var enabled) && enabled;
                // Only reset the lockout when TFA is not enabled when not in quirks mode
                if (alwaysLockout || !await IsTfaEnabled(user))
                {
                    await ResetLockout(user);
                }

                return SignInResult.Success;
            }
            Logger.LogWarning(2, "User {userId} failed to provide the correct password.", await UserManager.GetUserIdAsync(user));

            if (UserManager.SupportsUserLockout && lockoutOnFailure)
            {
                // If lockout is requested, increment access failed count which might lock out the user
                await UserManager.AccessFailedAsync(user);
                if (await UserManager.IsLockedOutAsync(user))
                {
                    return await LockedOut(user);
                }
            }
            return SignInResult.Failed;
        }

        /// <summary>
        /// 返回一个标志，该标志指示当前客户端浏览器是否已通过两因素身份验证记住
         ///对于尝试登录的用户，作为异步操作。
        /// </summary>
        /// <param name="user">The user attempting to login.</param>
        /// <returns>
        /// The task object representing the asynchronous operation containing true if the browser has been remembered
        /// for the current user.
        /// </returns>
        public virtual async Task<bool> IsTwoFactorClientRememberedAsync(TUser user)
        {
            var userId = await UserManager.GetUserIdAsync(user);
            var result = await Context.AuthenticateAsync(IdentityConstants.TwoFactorRememberMeScheme);
            return (result?.Principal != null && result.Principal.FindFirstValue(ClaimTypes.Name) == userId);
        }

        /// <summary>
        /// 在浏览器上设置一个标志，以指示用户已出于两个因素的身份验证目的选择了“记住此浏览器”，
         ///作为异步操作。
        /// </summary>
        /// <param name="user">The user who choose "remember this browser".</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual async Task RememberTwoFactorClientAsync(TUser user)
        {
            var principal = await StoreRememberClient(user);
            await Context.SignInAsync(IdentityConstants.TwoFactorRememberMeScheme,
                principal,
                new AuthenticationProperties { IsPersistent = true });
        }

        /// <summary>
        ///作为异步操作，从当前浏览器中清除“记住此浏览器标志”。
        /// </summary>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual Task ForgetTwoFactorClientAsync()
        {
            return Context.SignOutAsync(IdentityConstants.TwoFactorRememberMeScheme);
        }

        /// <summary>
        /// 使用两因素恢复代码在没有两因素身份验证的情况下登录用户。
        /// </summary>
        /// <param name="recoveryCode">两因素恢复码.</param>
        /// <returns></returns>
        public virtual async Task<SignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode)
        {
            var twoFactorInfo = await RetrieveTwoFactorInfoAsync();
            if (twoFactorInfo == null || twoFactorInfo.UserId == null)
            {
                return SignInResult.Failed;
            }
            var user = await UserManager.FindByIdAsync(twoFactorInfo.UserId);
            if (user == null)
            {
                return SignInResult.Failed;
            }

            var result = await UserManager.RedeemTwoFactorRecoveryCodeAsync(user, recoveryCode);
            if (result.Succeeded)
            {
                await DoTwoFactorSignInAsync(user, twoFactorInfo, isPersistent: false, rememberClient: false);
                return SignInResult.Success;
            }

            // We don't protect against brute force attacks since codes are expected to be random.
            return SignInResult.Failed;
        }

        private async Task DoTwoFactorSignInAsync(TUser user, TwoFactorAuthenticationInfo twoFactorInfo, bool isPersistent, bool rememberClient)
        {
            // When token is verified correctly, clear the access failed count used for lockout
            await ResetLockout(user);

            var claims = new List<Claim>();
            claims.Add(new Claim("amr", "mfa"));

            // Cleanup external cookie
            if (twoFactorInfo.LoginProvider != null)
            {
                claims.Add(new Claim(ClaimTypes.AuthenticationMethod, twoFactorInfo.LoginProvider));
                await Context.SignOutAsync(IdentityConstants.ExternalScheme);
            }
            // Cleanup two factor user id cookie
            await Context.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);
            if (rememberClient)
            {
                await RememberTwoFactorClientAsync(user);
            }
            await SignInWithClaimsAsync(user, isPersistent, claims);
        }

        /// <summary>
        /// 验证来自身份验证器应用程序的登录代码，并作为异步操作创建并登录用户。
        /// </summary>
        /// <param name="code">两因素验证码验证.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="rememberClient">Flag indicating whether the current browser should be remember, suppressing all further 
        /// two factor authentication prompts.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public virtual async Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
        {
            var twoFactorInfo = await RetrieveTwoFactorInfoAsync();
            if (twoFactorInfo == null || twoFactorInfo.UserId == null)
            {
                return SignInResult.Failed;
            }
            var user = await UserManager.FindByIdAsync(twoFactorInfo.UserId);
            if (user == null)
            {
                return SignInResult.Failed;
            }

            var error = await PreSignInCheck(user);
            if (error != null)
            {
                return error;
            }

            if (await UserManager.VerifyTwoFactorTokenAsync(user, Options.Tokens.AuthenticatorTokenProvider, code))
            {
                await DoTwoFactorSignInAsync(user, twoFactorInfo, isPersistent, rememberClient);
                return SignInResult.Success;
            }
            // If the token is incorrect, record the failure which also may cause the user to be locked out
            await UserManager.AccessFailedAsync(user);
            return SignInResult.Failed;
        }

        /// <summary>
        ///验证两个因素的登录代码，并以异步操作的形式创建并登录用户。
        /// </summary>
        /// <param name="provider">两因素身份验证提供程序来验证代码.</param>
        /// <param name="code">The two factor authentication code to validate.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="rememberClient">Flag indicating whether the current browser should be remember, suppressing all further 
        /// two factor authentication prompts.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public virtual async Task<SignInResult> TwoFactorSignInAsync(string provider, string code, bool isPersistent, bool rememberClient)
        {
            var twoFactorInfo = await RetrieveTwoFactorInfoAsync();
            if (twoFactorInfo == null || twoFactorInfo.UserId == null)
            {
                return SignInResult.Failed;
            }
            var user = await UserManager.FindByIdAsync(twoFactorInfo.UserId);
            if (user == null)
            {
                return SignInResult.Failed;
            }

            var error = await PreSignInCheck(user);
            if (error != null)
            {
                return error;
            }
            if (await UserManager.VerifyTwoFactorTokenAsync(user, provider, code))
            {
                await DoTwoFactorSignInAsync(user, twoFactorInfo, isPersistent, rememberClient);
                return SignInResult.Success;
            }
            // If the token is incorrect, record the failure which also may cause the user to be locked out
            await UserManager.AccessFailedAsync(user);
            return SignInResult.Failed;
        }

        /// <summary>
        /// 获取当前两因素身份验证登录的<typeparamref name =“ TUser” />作为异步操作。
        /// </summary>
        /// <returns>The task object representing the asynchronous operation containing the <typeparamref name="TUser"/>
        /// for the sign-in attempt.</returns>
        public virtual async Task<TUser> GetTwoFactorAuthenticationUserAsync()
        {
            var info = await RetrieveTwoFactorInfoAsync();
            if (info == null)
            {
                return null;
            }

            return await UserManager.FindByIdAsync(info.UserId);
        }

        /// <summary>
        /// 通过先前注册的第三方登录名登录用户，作为异步操作。
        /// </summary>
        /// <param name="loginProvider">The login provider to use.</param>
        /// <param name="providerKey">The unique provider identifier for the user.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public virtual Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent)
            => ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent, bypassTwoFactor: false);

        /// <summary>
        /// 通过先前注册的第三方登录名登录用户，作为异步操作。
        /// </summary>
        /// <param name="loginProvider">The login provider to use.</param>
        /// <param name="providerKey">The unique provider identifier for the user.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="bypassTwoFactor">指示是否绕过两因素身份验证的标志。</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult"/>
        /// for the sign-in attempt.</returns>
        public virtual async Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent, bool bypassTwoFactor)
        {
            var user = await UserManager.FindByLoginAsync(loginProvider, providerKey);
            if (user == null)
            {
                return SignInResult.Failed;
            }

            var error = await PreSignInCheck(user);
            if (error != null)
            {
                return error;
            }
            return await SignInOrTwoFactorAsync(user, isPersistent, loginProvider, bypassTwoFactor);
        }

        /// <summary>
        /// 获取已知外部登录提供程序的<see cref =“ AuthenticationScheme” />的集合。		
        /// </summary>		
        /// <returns>A collection of <see cref="AuthenticationScheme"/>s for the known external login providers.</returns>		
        public virtual async Task<IEnumerable<AuthenticationScheme>> GetExternalAuthenticationSchemesAsync()
        {
            var schemes = await _schemes.GetAllSchemesAsync();
            return schemes.Where(s => !string.IsNullOrEmpty(s.DisplayName));
        }

        /// <summary>
        ///作为异步操作，获取当前登录的外部登录信息。
        /// </summary>
        /// <param name="expectedXsrf">Flag indication whether a Cross Site Request Forgery token was expected in the current request.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="ExternalLoginInfo"/>
        /// for the sign-in attempt.</returns>
        public virtual async Task<ExternalLoginInfo> GetExternalLoginInfoAsync(string expectedXsrf = null)
        {
            var auth = await Context.AuthenticateAsync(IdentityConstants.ExternalScheme);
            var items = auth?.Properties?.Items;
            if (auth?.Principal == null || items == null || !items.ContainsKey(LoginProviderKey))
            {
                return null;
            }

            if (expectedXsrf != null)
            {
                if (!items.ContainsKey(XsrfKey))
                {
                    return null;
                }
                var userId = items[XsrfKey] as string;
                if (userId != expectedXsrf)
                {
                    return null;
                }
            }

            var providerKey = auth.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
            var provider = items[LoginProviderKey] as string;
            if (providerKey == null || provider == null)
            {
                return null;
            }

            var providerDisplayName = (await GetExternalAuthenticationSchemesAsync()).FirstOrDefault(p => p.Name == provider)?.DisplayName
                                      ?? provider;
            return new ExternalLoginInfo(auth.Principal, provider, providerKey, providerDisplayName)
            {
                AuthenticationTokens = auth.Properties.GetTokens(),
                AuthenticationProperties = auth.Properties
            };
        }

        /// <summary>
        ///将在外部身份验证cookie中找到的所有身份验证令牌存储到关联的用户中。
        /// </summary>
        /// <param name="externalLogin">The information from the external login provider.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the operation.</returns>
        public virtual async Task<IdentityResult> UpdateExternalAuthenticationTokensAsync(ExternalLoginInfo externalLogin)
        {
            if (externalLogin == null)
            {
                throw new ArgumentNullException(nameof(externalLogin));
            }

            if (externalLogin.AuthenticationTokens != null && externalLogin.AuthenticationTokens.Any())
            {
                var user = await UserManager.FindByLoginAsync(externalLogin.LoginProvider, externalLogin.ProviderKey);
                if (user == null)
                {
                    return IdentityResult.Failed();
                }

                foreach (var token in externalLogin.AuthenticationTokens)
                {
                    var result = await UserManager.SetAuthenticationTokenAsync(user, externalLogin.LoginProvider, token.Name, token.Value);
                    if (!result.Succeeded)
                    {
                        return result;
                    }
                }
            }

            return IdentityResult.Success;
        }

        /// <summary>
        ///为指定的外部登录名<paramref name =“ provider” />配置重定向URL和用户标识符。
        /// </summary>
        /// <param name="provider">The provider to configure.</param>
        /// <param name="redirectUrl">The external login URL users should be redirected to during the login flow.</param>
        /// <param name="userId">The current user's identifier, which will be used to provide CSRF protection.</param>
        /// <returns>A configured <see cref="AuthenticationProperties"/>.</returns>
        public virtual AuthenticationProperties ConfigureExternalAuthenticationProperties(string provider, string redirectUrl, string userId = null)
        {
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            properties.Items[LoginProviderKey] = provider;
            if (userId != null)
            {
                properties.Items[XsrfKey] = userId;
            }
            return properties;
        }

        /// <summary>
        ///为指定的2fa信息创建索赔主体。
        /// </summary>
        /// <param name="userId">The user whose is logging in via 2fa.</param>
        /// <param name="loginProvider">The 2fa provider.</param>
        /// <returns>A <see cref="ClaimsPrincipal"/> containing the user 2fa information.</returns>
        internal ClaimsPrincipal StoreTwoFactorInfo(string userId, string loginProvider)
        {
            var identity = new ClaimsIdentity(IdentityConstants.TwoFactorUserIdScheme);
            identity.AddClaim(new Claim(ClaimTypes.Name, userId));
            if (loginProvider != null)
            {
                identity.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, loginProvider));
            }
            return new ClaimsPrincipal(identity);
        }

        internal async Task<ClaimsPrincipal> StoreRememberClient(TUser user)
        {
            var userId = await UserManager.GetUserIdAsync(user);
            var rememberBrowserIdentity = new ClaimsIdentity(IdentityConstants.TwoFactorRememberMeScheme);
            rememberBrowserIdentity.AddClaim(new Claim(ClaimTypes.Name, userId));
            if (UserManager.SupportsUserSecurityStamp)
            {
                var stamp = await UserManager.GetSecurityStampAsync(user);
                rememberBrowserIdentity.AddClaim(new Claim(Options.ClaimsIdentity.SecurityStampClaimType, stamp));
            }
            return new ClaimsPrincipal(rememberBrowserIdentity);
        }

        private ClaimsIdentity CreateIdentity(TwoFactorAuthenticationInfo info)
        {
            if (info == null)
            {
                return null;
            }
            var identity = new ClaimsIdentity(IdentityConstants.TwoFactorUserIdScheme);
            identity.AddClaim(new Claim(ClaimTypes.Name, info.UserId));
            if (info.LoginProvider != null)
            {
                identity.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, info.LoginProvider));
            }
            return identity;
        }

        private async Task<bool> IsTfaEnabled(TUser user)
            => UserManager.SupportsUserTwoFactor &&
            await UserManager.GetTwoFactorEnabledAsync(user) &&
            (await UserManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;

        /// <summary>
        /// 如果<paramref name =“ bypassTwoFactor” />设置为false，则登录指定的<paramref name =“ user” />。
         ///否则，将存储<paramref name =“ user” />，以进行两因素检查后使用。
        /// </summary>
        /// <param name="user"></param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="loginProvider">The login provider to use. Default is null</param>
        /// <param name="bypassTwoFactor">Flag indicating whether to bypass two factor authentication. Default is false</param>
        /// <returns>Returns a <see cref="SignInResult"/></returns>
        protected virtual async Task<SignInResult> SignInOrTwoFactorAsync(TUser user, bool isPersistent, string loginProvider = null, bool bypassTwoFactor = false)
        {
            if (!bypassTwoFactor && await IsTfaEnabled(user))
            {
                if (!await IsTwoFactorClientRememberedAsync(user))
                {
                    // Store the userId for use after two factor check
                    var userId = await UserManager.GetUserIdAsync(user);
                    await Context.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, StoreTwoFactorInfo(userId, loginProvider));
                    return SignInResult.TwoFactorRequired;
                }
            }
            // Cleanup external cookie
            if (loginProvider != null)
            {
                await Context.SignOutAsync(IdentityConstants.ExternalScheme);
            }
            if (loginProvider == null)
            {
                await SignInWithClaimsAsync(user, isPersistent, new Claim[] { new Claim("amr", "pwd") });
            }
            else
            {
                await SignInAsync(user, isPersistent, loginProvider);
            }
            return SignInResult.Success;
        }

        private async Task<TwoFactorAuthenticationInfo> RetrieveTwoFactorInfoAsync()
        {
            var result = await Context.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);
            if (result?.Principal != null)
            {
                return new TwoFactorAuthenticationInfo
                {
                    UserId = result.Principal.FindFirstValue(ClaimTypes.Name),
                    LoginProvider = result.Principal.FindFirstValue(ClaimTypes.AuthenticationMethod)
                };
            }
            return null;
        }

        /// <summary>
        /// 用于确定是否认为用户被锁定。
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>Whether a user is considered locked out.</returns>
        protected virtual async Task<bool> IsLockedOut(TUser user)
        {
            return UserManager.SupportsUserLockout && await UserManager.IsLockedOutAsync(user);
        }

        /// <summary>
        /// 返回锁定的SignInResult。
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>A locked out SignInResult</returns>
        protected virtual async Task<SignInResult> LockedOut(TUser user)
        {
            Logger.LogWarning(3, "User {userId} is currently locked out.", await UserManager.GetUserIdAsync(user));
            return SignInResult.LockedOut;
        }

        /// <summary>
        ///用于确保允许用户登录。
        /// </summary>
        /// <param name="user">The user</param>
        /// <returns>Null if the user should be allowed to sign in, otherwise the SignInResult why they should be denied.</returns>
        protected virtual async Task<SignInResult> PreSignInCheck(TUser user)
        {
            if (!await CanSignInAsync(user))
            {
                return SignInResult.NotAllowed;
            }
            if (await IsLockedOut(user))
            {
                return await LockedOut(user);
            }
            return null;
        }

        /// <summary>
        /// 用于重置用户的锁定计数。
        /// </summary>
        /// <param name="user">The user</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the operation.</returns>
        protected virtual Task ResetLockout(TUser user)
        {
            if (UserManager.SupportsUserLockout)
            {
                return UserManager.ResetAccessFailedCountAsync(user);
            }
            return Task.CompletedTask;
        }

        internal class TwoFactorAuthenticationInfo
        {
            public string UserId { get; set; }
            public string LoginProvider { get; set; }
        }
    }
```
### TwoFactorSecurityStampValidator
```
    /// <summary>
    ///负责验证两因素身份Cookie安全标记。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public class TwoFactorSecurityStampValidator<TUser> : SecurityStampValidator<TUser>, ITwoFactorSecurityStampValidator where TUser : class
    {
        /// <summary>
        /// 创建<see cref =“ SecurityStampValidator {TUser}” />的新实例。
        /// </summary>
        /// <param name="options">Used to access the <see cref="IdentityOptions"/>.</param>
        /// <param name="signInManager">The <see cref="SignInManager{TUser}"/>.</param>
        /// <param name="clock">The system clock.</param>
        /// <param name="logger">The logger.</param>
        public TwoFactorSecurityStampValidator(IOptions<SecurityStampValidatorOptions> options, SignInManager<TUser> signInManager, ISystemClock clock, ILoggerFactory logger) : base(options, signInManager, clock, logger)
        { }

        /// <summary>
        /// 验证主体的安全标记，如果成功，则返回匹配的用户
        /// </summary>
        /// <param name="principal">The principal to verify.</param>
        /// <returns>The verified user or null if verification fails.</returns>
        protected override Task<TUser> VerifySecurityStamp(ClaimsPrincipal principal)
            => SignInManager.ValidateTwoFactorSecurityStampAsync(principal);

        /// <summary>
        /// 验证安全标记后调用。
        /// </summary>
        /// <param name="user">The user who has been verified.</param>
        /// <param name="context">The <see cref="CookieValidatePrincipalContext"/>.</param>
        /// <returns>A task.</returns>
        protected override Task SecurityStampVerified(TUser user, CookieValidatePrincipalContext context)
            => Task.CompletedTask;
    }
```