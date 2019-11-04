|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AuthenticationCoreServiceCollectionExtensions](#authenticationcoreservicecollectionextensions)
* [AuthenticationFeature](#authenticationfeature)
* [AuthenticationHandlerProvider](#authenticationhandlerprovider)
* [AuthenticationSchemeProvider](#authenticationschemeprovider)
* [AuthenticationService](#authenticationservice)
* [NoopClaimsTransformation](#noopclaimstransformation)

### AuthenticationCoreServiceCollectionExtensions
    //在<see cref =“ IServiceCollection” />中设置身份验证服务的扩展方法。
```
        /// <summary>
        /// 添加<see cref =“ IAuthenticationService” />所需的核心身份验证服务。
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <returns>The service collection.</returns>
        public static IServiceCollection AddAuthenticationCore(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.TryAddScoped<IAuthenticationService, AuthenticationService>();
            services.TryAddSingleton<IClaimsTransformation, NoopClaimsTransformation>(); // Can be replaced with scoped ones that use DbContext
            services.TryAddScoped<IAuthenticationHandlerProvider, AuthenticationHandlerProvider>();
            services.TryAddSingleton<IAuthenticationSchemeProvider, AuthenticationSchemeProvider>();
            return services;
        }
```
```
     /// <summary>
        /// 添加<see cref =“ IAuthenticationService” />所需的核心身份验证服务。
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="configureOptions">用于配置<see cref =“ AuthenticationOptions” />。</param>
        /// <returns>The service collection.</returns>
        public static IServiceCollection AddAuthenticationCore(this IServiceCollection services, Action<AuthenticationOptions> configureOptions) {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            services.AddAuthenticationCore();
            services.Configure(configureOptions);
            return services;
        }
```

### AuthenticationFeatur
    //用于捕获路径信息，因此可以在app.Map（）中正确计算重定向。
```
        /// <summary>
        /// The original path base.
        /// </summary>
        public PathString OriginalPathBase { get; set; }

        /// <summary>
        /// The original path.
        /// </summary>
        public PathString OriginalPath { get; set; }
```

### AuthenticationHandlerProvider
    //<see cref =“ IAuthenticationHandlerProvider” />的实现。
```
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="schemes">The <see cref="IAuthenticationHandlerProvider"/>.</param>
        public AuthenticationHandlerProvider(IAuthenticationSchemeProvider schemes)
        {
            Schemes = schemes;
        }

        /// <summary>
        /// The <see cref="IAuthenticationHandlerProvider"/>.
        /// </summary>
        public IAuthenticationSchemeProvider Schemes { get; }

        // 处理程序实例缓存，每个请求需要初始化一次
        private Dictionary<string, IAuthenticationHandler> _handlerMap = new Dictionary<string, IAuthenticationHandler>(StringComparer.Ordinal);


```
```
        /// <summary>
        /// 返回将使用的处理程序实例。
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="authenticationScheme">正在处理的认证方案的名称.</param>
        /// <returns>The handler instance.</returns>
        public async Task<IAuthenticationHandler> GetHandlerAsync(HttpContext context, string authenticationScheme)
        {
            if (_handlerMap.ContainsKey(authenticationScheme))
            {
                return _handlerMap[authenticationScheme];
            }

            var scheme = await Schemes.GetSchemeAsync(authenticationScheme);
            if (scheme == null)
            {
                return null;
            }
            var handler = (context.RequestServices.GetService(scheme.HandlerType) ??
                ActivatorUtilities.CreateInstance(context.RequestServices, scheme.HandlerType))
                as IAuthenticationHandler;
            if (handler != null)
            {
                await handler.InitializeAsync(scheme, context);
                _handlerMap[authenticationScheme] = handler;
            }
            return handler;
        }
```
### AuthenticationSchemeProvider
实现<see cref =“ IAuthenticationSchemeProvider” />。
   AuthenticationSchemeProvider : IAuthenticationSchemeProvider
```
        /// <summary>
        ///创建<see cref =“ AuthenticationSchemeProvider” />的实例
         ///使用指定的<paramref name =“ options” />，
        /// </summary>
        /// <param name="options">The <see cref="AuthenticationOptions"/> options.</param>
        public AuthenticationSchemeProvider(IOptions<AuthenticationOptions> options)
            : this(options, new Dictionary<string, AuthenticationScheme>(StringComparer.Ordinal))
        {
        }

        /// <summary>
        /// 创建<see cref =“ AuthenticationSchemeProvider” />的实例
         ///使用指定的<paramref name =“ options” />和<paramref name =“ schemes” />。
        /// </summary>
        /// <param name="options">The <see cref="AuthenticationOptions"/> options.</param>
        /// <param name="schemes">The dictionary used to store authentication schemes.</param>
        protected AuthenticationSchemeProvider(IOptions<AuthenticationOptions> options, IDictionary<string, AuthenticationScheme> schemes)
        {
            _options = options.Value;

            _schemes = schemes ?? throw new ArgumentNullException(nameof(schemes));
            _requestHandlers = new List<AuthenticationScheme>();

            foreach (var builder in _options.Schemes)
            {
                var scheme = builder.Build();
                AddScheme(scheme);
            }
        }
```
```
        private readonly AuthenticationOptions _options;
        private readonly object _lock = new object();

        private readonly IDictionary<string, AuthenticationScheme> _schemes;
        private readonly List<AuthenticationScheme> _requestHandlers;
        // Used as a safe return value for enumeration apis
        private IEnumerable<AuthenticationScheme> _schemesCopy = Array.Empty<AuthenticationScheme>();
        private IEnumerable<AuthenticationScheme> _requestHandlersCopy = Array.Empty<AuthenticationScheme>();
```
```
        private Task<AuthenticationScheme> GetDefaultSchemeAsync()
            => _options.DefaultScheme != null
            ? GetSchemeAsync(_options.DefaultScheme)
            : Task.FromResult<AuthenticationScheme>(null);
```
```
        /// <summary>
        返回默认情况下将用于<see cref =“ IAuthenticationService.AuthenticateAsync（HttpContext，string）” />的方案。
         ///通常通过<see cref =“ AuthenticationOptions.DefaultAuthenticateScheme” />指定。
         ///否则，它将回退到<see cref =“ AuthenticationOptions.DefaultScheme” />。
        /// </summary>
        /// <returns>默认情况下将用于<see cref =“ IAuthenticationService.AuthenticateAsync（HttpContext，string）” />的方案。</returns>
        public virtual Task<AuthenticationScheme> GetDefaultAuthenticateSchemeAsync()
            => _options.DefaultAuthenticateScheme != null
            ? GetSchemeAsync(_options.DefaultAuthenticateScheme)
            : GetDefaultSchemeAsync();
```
```
       /// <summary>
        /// 返回默认情况下将用于<see cref =“ IAuthenticationService.ChallengeAsync（HttpContext，string，AuthenticationProperties）” />的方案。
         ///通常通过<see cref =“ AuthenticationOptions.DefaultChallengeScheme” />指定。
         ///否则，它将回退到<see cref =“ AuthenticationOptions.DefaultScheme” />。
        /// </summary>
        /// <returns>默认情况下将用于<see cref =“ IAuthenticationService.ChallengeAsync（HttpContext，string，AuthenticationProperties）” />的方案.</returns>
        public virtual Task<AuthenticationScheme> GetDefaultChallengeSchemeAsync()
            => _options.DefaultChallengeScheme != null
            ? GetSchemeAsync(_options.DefaultChallengeScheme)
            : GetDefaultSchemeAsync();
```
```
        /// <summary>
        /// 返回默认情况下将用于<see cref =“ IAuthenticationService.ForbidAsync（HttpContext，string，AuthenticationProperties）” />的方案。
         ///通常是通过<see cref =“ AuthenticationOptions.DefaultForbidScheme” />指定的。
         ///否则，它将回退到<see cref =“ GetDefaultChallengeSchemeAsync” />。
        /// </summary>
        /// <returns>默认情况下将用于<参见cref =“ IAuthenticationService.ForbidAsync（HttpContext，string，AuthenticationProperties）” />的方案。</returns>
        public virtual Task<AuthenticationScheme> GetDefaultForbidSchemeAsync()
            => _options.DefaultForbidScheme != null
            ? GetSchemeAsync(_options.DefaultForbidScheme)
            : GetDefaultChallengeSchemeAsync();
```
```
        /// <summary>
        /// 返回默认情况下将用于<see cref =“ IAuthenticationService.SignInAsync（HttpContext，string，System.Security.Claims.ClaimsPrincipal，AuthenticationProperties）” />的方案。
         ///通常是通过<see cref =“ AuthenticationOptions.DefaultSignInScheme” />指定。
         ///否则，它将回退到<see cref =“ AuthenticationOptions.DefaultScheme” />。
        /// </summary>
        /// <returns>默认情况下将用于<参见cref =“ IAuthenticationService.SignInAsync（HttpContext，string，System.Security.Claims.ClaimsPrincipal，AuthenticationProperties）” />的方案。</returns>
        public virtual Task<AuthenticationScheme> GetDefaultSignInSchemeAsync()
            => _options.DefaultSignInScheme != null
            ? GetSchemeAsync(_options.DefaultSignInScheme)
            : GetDefaultSchemeAsync();
```
```
        /// <summary>
        /// 返回默认情况下将用于<see cref =“ IAuthenticationService.SignOutAsync（HttpContext，string，AuthenticationProperties）” />的方案。
         ///通常通过<see cref =“ AuthenticationOptions.DefaultSignOutScheme” />指定。
         ///否则，如果支持退出，它将回退到<see cref =“ GetDefaultSignInSchemeAsync” />。
        /// </summary>
        /// <returns>默认情况下将用于<参见cref =“ IAuthenticationService.SignOutAsync（HttpContext，string，AuthenticationProperties）” />的方案。</returns>
        public virtual Task<AuthenticationScheme> GetDefaultSignOutSchemeAsync()
            => _options.DefaultSignOutScheme != null
            ? GetSchemeAsync(_options.DefaultSignOutScheme)
            : GetDefaultSignInSchemeAsync();
```
```
        /// <summary>
        /// 返回与名称匹配的<see cref =“ AuthenticationScheme” />或null。
        /// </summary>
        /// <param name="name">authenticationScheme的名称.</param>
        /// <returns>方案；如果找不到，则为null.</returns>
        public virtual Task<AuthenticationScheme> GetSchemeAsync(string name)
            => Task.FromResult(_schemes.ContainsKey(name) ? _schemes[name] : null);
```
```
    /// <summary>
        /// 以优先级顺序返回方案以进行请求处理。
        /// </summary>
        /// <returns>按优先级顺序处理请求的方案</returns>
        public virtual Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync()
            => Task.FromResult(_requestHandlersCopy);
```
```
        /// <summary>
        /// 注册供<see cref =“ IAuthenticationService” />使用的方案。 
        /// </summary>
        /// <param name="scheme">The scheme.</param>
        public virtual void AddScheme(AuthenticationScheme scheme)
        {
            if (_schemes.ContainsKey(scheme.Name))
            {
                throw new InvalidOperationException("Scheme already exists: " + scheme.Name);
            }
            lock (_lock)
            {
                if (_schemes.ContainsKey(scheme.Name))
                {
                    throw new InvalidOperationException("Scheme already exists: " + scheme.Name);
                }
                if (typeof(IAuthenticationRequestHandler).IsAssignableFrom(scheme.HandlerType))
                {
                    _requestHandlers.Add(scheme);
                    _requestHandlersCopy = _requestHandlers.ToArray();
                }
                _schemes[scheme.Name] = scheme;
                _schemesCopy = _schemes.Values.ToArray();
            }
        }
```
```
        /// <summary>
        /// 删除一个方案，以防止它被<see cref =“ IAuthenticationService” />使用。
        /// </summary>
        /// <param name="name">The name of the authenticationScheme being removed.</param>
        public virtual void RemoveScheme(string name)
        {
            if (!_schemes.ContainsKey(name))
            {
                return;
            }
            lock (_lock)
            {
                if (_schemes.ContainsKey(name))
                {
                    var scheme = _schemes[name];
                    if (_requestHandlers.Remove(scheme))
                    {
                        _requestHandlersCopy = _requestHandlers.ToArray();
                    }
                    _schemes.Remove(name);
                    _schemesCopy = _schemes.Values.ToArray();
                }
            }
        }
```
```
        public virtual Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync()
            => Task.FromResult(_schemesCopy);
```
### AuthenticationService 
    //实现<see cref =“ IAuthenticationService” />。
```
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="schemes">The <see cref="IAuthenticationSchemeProvider"/>.</param>
        /// <param name="handlers">The <see cref="IAuthenticationHandlerProvider"/>.</param>
        /// <param name="transform">The <see cref="IClaimsTransformation"/>.</param>
        /// <param name="options">The <see cref="AuthenticationOptions"/>.</param>
        public AuthenticationService(IAuthenticationSchemeProvider schemes, IAuthenticationHandlerProvider handlers, IClaimsTransformation transform, IOptions<AuthenticationOptions> options)
        {
            Schemes = schemes;
            Handlers = handlers;
            Transform = transform;
            Options = options.Value;
        }
```
```
        /// <summary>
        /// 用于查找AuthenticationSchemes。
        /// </summary>
        public IAuthenticationSchemeProvider Schemes { get; }

        /// <summary>
        /// 用于解析IAuthenticationHandler实例。
        /// </summary>
        public IAuthenticationHandlerProvider Handlers { get; }

        /// <summary>
        ///用于Claims转换。
        /// </summary>
        public IClaimsTransformation Transform { get; }

        /// <summary>
        /// The <see cref="AuthenticationOptions"/>.
        /// </summary>
        public AuthenticationOptions Options { get; }
```
```
        /// <summary>
        /// 针对指定的身份验证方案进行身份验证。
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="scheme">The name of the authentication scheme.</param>
        /// <returns>The result.</returns>
        public virtual async Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string scheme)
        {
            if (scheme == null)
            {
                var defaultScheme = await Schemes.GetDefaultAuthenticateSchemeAsync();
                scheme = defaultScheme?.Name;
                if (scheme == null)
                {
                    throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultAuthenticateScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
                }
            }

            var handler = await Handlers.GetHandlerAsync(context, scheme);
            if (handler == null)
            {
                throw await CreateMissingHandlerException(scheme);
            }

            var result = await handler.AuthenticateAsync();
            if (result != null && result.Succeeded)
            {
                var transformed = await Transform.TransformAsync(result.Principal);
                return AuthenticateResult.Success(new AuthenticationTicket(transformed, result.Properties, result.Ticket.AuthenticationScheme));
            }
            return result;
        }
```
```
        /// <summary>
        /// 握手指定的身份验证方案。
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="scheme">The name of the authentication scheme.</param>
        /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
        /// <returns>A task.</returns>
        public virtual async Task ChallengeAsync(HttpContext context, string scheme, AuthenticationProperties properties)
        {
            if (scheme == null)
            {
                var defaultChallengeScheme = await Schemes.GetDefaultChallengeSchemeAsync();
                scheme = defaultChallengeScheme?.Name;
                if (scheme == null)
                {
                    throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultChallengeScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
                }
            }

            var handler = await Handlers.GetHandlerAsync(context, scheme);
            if (handler == null)
            {
                throw await CreateMissingHandlerException(scheme);
            }

            await handler.ChallengeAsync(properties);
        }
```
```
        /// <summary>
        /// 禁止指定的认证方案。
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="scheme">The name of the authentication scheme.</param>
        /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
        /// <returns>A task.</returns>
        public virtual async Task ForbidAsync(HttpContext context, string scheme, AuthenticationProperties properties)
        {
            if (scheme == null)
            {
                var defaultForbidScheme = await Schemes.GetDefaultForbidSchemeAsync();
                scheme = defaultForbidScheme?.Name;
                if (scheme == null)
                {
                    throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultForbidScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
                }
            }

            var handler = await Handlers.GetHandlerAsync(context, scheme);
            if (handler == null)
            {
                throw await CreateMissingHandlerException(scheme);
            }

            await handler.ForbidAsync(properties);
        }

```
```
        /// <summary>
        /// 登录指定身份验证方案的主体。
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="scheme">The name of the authentication scheme.</param>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> to sign in.</param>
        /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
        /// <returns>A task.</returns>
        public virtual async Task SignInAsync(HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (Options.RequireAuthenticatedSignIn)
            {
                if (principal.Identity == null)
                {
                    throw new InvalidOperationException("SignInAsync when principal.Identity == null is not allowed when AuthenticationOptions.RequireAuthenticatedSignIn is true.");
                }
                if (!principal.Identity.IsAuthenticated)
                {
                    throw new InvalidOperationException("SignInAsync when principal.Identity.IsAuthenticated is false is not allowed when AuthenticationOptions.RequireAuthenticatedSignIn is true.");
                }
            }

            if (scheme == null)
            {
                var defaultScheme = await Schemes.GetDefaultSignInSchemeAsync();
                scheme = defaultScheme?.Name;
                if (scheme == null)
                {
                    throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultSignInScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
                }
            }

            var handler = await Handlers.GetHandlerAsync(context, scheme);
            if (handler == null)
            {
                throw await CreateMissingSignInHandlerException(scheme);
            }

            var signInHandler = handler as IAuthenticationSignInHandler;
            if (signInHandler == null)
            {
                throw await CreateMismatchedSignInHandlerException(scheme, handler);
            }

            await signInHandler.SignInAsync(principal, properties);
        }
```
```
        /// <summary>
        /// 注销指定的身份验证方案。
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="scheme">The name of the authentication scheme.</param>
        /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
        /// <returns>A task.</returns>
        public virtual async Task SignOutAsync(HttpContext context, string scheme, AuthenticationProperties properties)
        {
            if (scheme == null)
            {
                var defaultScheme = await Schemes.GetDefaultSignOutSchemeAsync();
                scheme = defaultScheme?.Name;
                if (scheme == null)
                {
                    throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultSignOutScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
                }
            }

            var handler = await Handlers.GetHandlerAsync(context, scheme);
            if (handler == null)
            {
                throw await CreateMissingSignOutHandlerException(scheme);
            }

            var signOutHandler = handler as IAuthenticationSignOutHandler;
            if (signOutHandler == null)
            {
                throw await CreateMismatchedSignOutHandlerException(scheme, handler);
            }

            await signOutHandler.SignOutAsync(properties);
        }
```
```
        //返回异常信息
        private async Task<Exception> CreateMissingHandlerException(string scheme)
        {
            var schemes = string.Join(", ", (await Schemes.GetAllSchemesAsync()).Select(sch => sch.Name));

            var footer = $" Did you forget to call AddAuthentication().Add[SomeAuthHandler](\"{scheme}\",...)?";

            if (string.IsNullOrEmpty(schemes))
            {
                return new InvalidOperationException(
                    $"No authentication handlers are registered." + footer);
            }

            return new InvalidOperationException(
                $"No authentication handler is registered for the scheme '{scheme}'. The registered schemes are: {schemes}." + footer);
        }

        private async Task<string> GetAllSignInSchemeNames()
        {
            return string.Join(", ", (await Schemes.GetAllSchemesAsync())
                .Where(sch => typeof(IAuthenticationSignInHandler).IsAssignableFrom(sch.HandlerType))
                .Select(sch => sch.Name));
        }

        private async Task<Exception> CreateMissingSignInHandlerException(string scheme)
        {
            var schemes = await GetAllSignInSchemeNames();

            // CookieAuth is the only implementation of sign-in.
            var footer = $" Did you forget to call AddAuthentication().AddCookies(\"{scheme}\",...)?";

            if (string.IsNullOrEmpty(schemes))
            {
                return new InvalidOperationException(
                    $"No sign-in authentication handlers are registered." + footer);
            }

            return new InvalidOperationException(
                $"No sign-in authentication handler is registered for the scheme '{scheme}'. The registered sign-in schemes are: {schemes}." + footer);
        }

        private async Task<Exception> CreateMismatchedSignInHandlerException(string scheme, IAuthenticationHandler handler)
        {
            var schemes = await GetAllSignInSchemeNames();

            var mismatchError = $"The authentication handler registered for scheme '{scheme}' is '{handler.GetType().Name}' which cannot be used for SignInAsync. ";

            if (string.IsNullOrEmpty(schemes))
            {
                // CookieAuth is the only implementation of sign-in.
                return new InvalidOperationException(mismatchError
                    + $"Did you forget to call AddAuthentication().AddCookies(\"Cookies\") and SignInAsync(\"Cookies\",...)?");
            }

            return new InvalidOperationException(mismatchError + $"The registered sign-in schemes are: {schemes}.");
        }
                private async Task<string> GetAllSignOutSchemeNames()
        {
            return string.Join(", ", (await Schemes.GetAllSchemesAsync())
                .Where(sch => typeof(IAuthenticationSignOutHandler).IsAssignableFrom(sch.HandlerType))
                .Select(sch => sch.Name));
        }

        private async Task<Exception> CreateMissingSignOutHandlerException(string scheme)
        {
            var schemes = await GetAllSignOutSchemeNames();

            var footer = $" Did you forget to call AddAuthentication().AddCookies(\"{scheme}\",...)?";

            if (string.IsNullOrEmpty(schemes))
            {
                // CookieAuth is the most common implementation of sign-out, but OpenIdConnect and WsFederation also support it.
                return new InvalidOperationException($"No sign-out authentication handlers are registered." + footer);
            }

            return new InvalidOperationException(
                $"No sign-out authentication handler is registered for the scheme '{scheme}'. The registered sign-out schemes are: {schemes}." + footer);
        }

        private async Task<Exception> CreateMismatchedSignOutHandlerException(string scheme, IAuthenticationHandler handler)
        {
            var schemes = await GetAllSignOutSchemeNames();

            var mismatchError = $"The authentication handler registered for scheme '{scheme}' is '{handler.GetType().Name}' which cannot be used for {nameof(SignOutAsync)}. ";

            if (string.IsNullOrEmpty(schemes))
            {
                // CookieAuth is the most common implementation of sign-out, but OpenIdConnect and WsFederation also support it.
                return new InvalidOperationException(mismatchError
                    + $"Did you forget to call AddAuthentication().AddCookies(\"Cookies\") and {nameof(SignOutAsync)}(\"Cookies\",...)?");
            }

            return new InvalidOperationException(mismatchError + $"The registered sign-out schemes are: {schemes}.");
        }
```
### NoopClaimsTransformation
    //默认声明转换是无操作的。
```
    public class NoopClaimsTransformation : IClaimsTransformation
    {
        /// <summary>
        /// 返回不变的主体。
        /// </summary>
        /// <param name="principal">The user.</param>
        /// <returns>The principal unchanged.</returns>
        public virtual Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            return Task.FromResult(principal);
        }
    }
```