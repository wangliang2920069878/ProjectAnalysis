|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [Event](/article//aspnetcore/Security/Authentication/Event.md)
* [AuthAppBuilderExtensions](#authappbuilderextensions)
* [AuthenticationBuilder](#authenticationbuilder)
* [AuthenticationHandler](#authenticationhandler)
* [AuthenticationMiddleware](#authenticationmiddleware)
* [AuthenticationSchemeOptions](#authenticationschemeoptions)
* [AuthenticationServiceCollectionExtensions](#authenticationservicecollectionextensions)
* [HandleRequestResult](#handlerequestresult)
* [PolicySchemeHandler](#policyschemehandler)
* [RemoteAuthenticationHandler](#remoteauthenticationhandler)
* [RemoteAuthenticationOptions](#remoteauthenticationoptions)
* [RequestPathBaseCookieBuilder](#requestpathbasecookiebuilder)
* [SignInAuthenticationHandler](#signinauthenticationhandler)
* [SignOutAuthenticationHandler](#signoutauthenticationhandler)
### AuthAppBuilderExtensions
    //用于向HTTP应用程序管道添加身份验证功能的扩展方法。
```
 /// <summary>
        /// 将<see cref =“ AuthenticationMiddleware” />添加到指定的<see cref =“ IApplicationBuilder” />，这将启用身份验证功能。
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
        /// <returns>操作完成后对此实例的引用。</returns>
        public static IApplicationBuilder UseAuthentication(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            
            return app.UseMiddleware<AuthenticationMiddleware>();
        }
```

### AuthenticationBuilder
    //用于配置身份验证
```
        public AuthenticationBuilder(IServiceCollection services)
            => Services = services;

        /// <summary>
        /// The services being configured.
        /// </summary>
        public virtual IServiceCollection Services { get; }
```
```
        private AuthenticationBuilder AddSchemeHelper<TOptions, THandler>(string authenticationScheme, string displayName, Action<TOptions> configureOptions)
            where TOptions : AuthenticationSchemeOptions, new()
            where THandler : class, IAuthenticationHandler
        {
            Services.Configure<AuthenticationOptions>(o =>
            {
                o.AddScheme(authenticationScheme, scheme => {
                    scheme.HandlerType = typeof(THandler);
                    scheme.DisplayName = displayName;
                });
            });
            if (configureOptions != null)
            {
                Services.Configure(authenticationScheme, configureOptions);
            }
            Services.AddOptions<TOptions>(authenticationScheme).Validate(o => {
                o.Validate(authenticationScheme);
                return true;
            });
            Services.AddTransient<THandler>();
            return this;
        }
```
```
        /// <summary>
        /// 添加一个<see cref =“ AuthenticationScheme” />，可由<see cref =“ IAuthenticationService” />使用。
        /// </summary>
        /// <typeparam name="TOptions"><see cref =“ AuthenticationSchemeOptions” />类型以配置处理程序。“ /></typeparam>
        /// <typeparam name="THandler"><see cref =“ AuthenticationHandler {TOptions}” /> />用于处理此方案。</typeparam>
        /// <param name="authenticationScheme">该方案的名称.</param>
        /// <param name="displayName">该方案的显示名称。</param>
        /// <param name="configureOptions">用于配置方案选项。</param>
        /// <returns>The builder.</returns>
        public virtual AuthenticationBuilder AddScheme<TOptions, THandler>(string authenticationScheme, string displayName, Action<TOptions> configureOptions)
            where TOptions : AuthenticationSchemeOptions, new()
            where THandler : AuthenticationHandler<TOptions>
            => AddSchemeHelper<TOptions, THandler>(authenticationScheme, displayName, configureOptions);
```
```
        /// <summary>
        /// 添加一个<see cref =“ AuthenticationScheme” />，可由<see cref =“ IAuthenticationService” />使用。
        /// </summary>
        /// <typeparam name="TOptions"><see cref =“ AuthenticationSchemeOptions” />类型以配置处理程序。“ />.</typeparam>
        /// <typeparam name="THandler"><see cref =“ AuthenticationHandler {TOptions}” /> />用于处理此方案。</typeparam>
        /// <param name="authenticationScheme">该方案的名称.</param>
        /// <param name="configureOptions">用于配置方案选项。</param>
        /// <returns>The builder.</returns>
        public virtual AuthenticationBuilder AddScheme<TOptions, THandler>(string authenticationScheme, Action<TOptions> configureOptions)
            where TOptions : AuthenticationSchemeOptions, new()
            where THandler : AuthenticationHandler<TOptions>
            => AddScheme<TOptions, THandler>(authenticationScheme, displayName: null, configureOptions: configureOptions);
```
```
/// <summary>
        /// 添加基于<see cref =“ RemoteAuthenticationHandler {TOptions}” /> />的基于<see cref =“ AuthenticationScheme” />的支持远程身份验证
         ///可以由<see cref =“ IAuthenticationService” />使用。
        /// </summary>
        /// <typeparam name="TOptions"><see cref =“ RemoteAuthenticationOptions” />类型以配置处理程序。“ />.</typeparam>
        /// <typeparam name="THandler"><see cref =“ RemoteAuthenticationHandler {TOptions}” /> />用于处理此方案。</typeparam>
        /// <param name="authenticationScheme">该方案的名称.</param>
        /// <param name="displayName">该方案的显示名称.</param>
        /// <param name="configureOptions">该方案的显示名称.</param>
        /// <returns>The builder.</returns>
        public virtual AuthenticationBuilder AddRemoteScheme<TOptions, THandler>(string authenticationScheme, string displayName, Action<TOptions> configureOptions)
            where TOptions : RemoteAuthenticationOptions, new()
            where THandler : RemoteAuthenticationHandler<TOptions>
        {
            Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, EnsureSignInScheme<TOptions>>());
            return AddScheme<TOptions, THandler>(authenticationScheme, displayName, configureOptions: configureOptions);
        }
```
```
        /// <summary>
        /// 添加基于<see cref =“ PolicySchemeHandler” />的身份验证处理程序，该处理程序可用于
         ///重定向到其他身份验证方案。
        /// </summary>
        /// <param name="authenticationScheme">该方案的名称.</param>
        /// <param name="displayName">该方案的显示名称。</param>
        /// <param name="configureOptions">用于配置方案选项.</param>
        /// <returns>The builder.</returns>
        public virtual AuthenticationBuilder AddPolicyScheme(string authenticationScheme, string displayName, Action<PolicySchemeOptions> configureOptions)
            => AddSchemeHelper<PolicySchemeOptions, PolicySchemeHandler>(authenticationScheme, displayName, configureOptions);
```
```
        // 用于确保始终存在并非其本身的默认登录方案
        private class EnsureSignInScheme<TOptions> : IPostConfigureOptions<TOptions> where TOptions : RemoteAuthenticationOptions
        {
            private readonly AuthenticationOptions _authOptions;

            public EnsureSignInScheme(IOptions<AuthenticationOptions> authOptions)
            {
                _authOptions = authOptions.Value;
            }

            public void PostConfigure(string name, TOptions options)
            {
                options.SignInScheme = options.SignInScheme ?? _authOptions.DefaultSignInScheme ?? _authOptions.DefaultScheme;
            }
        }
```
### AuthenticationHandler
    //AuthenticationHandler<TOptions> : IAuthenticationHandler where TOptions : AuthenticationSchemeOptions, new()
```
        private Task<AuthenticateResult> _authenticateTask;

        public AuthenticationScheme Scheme { get; private set; }
        public TOptions Options { get; private set; }
        protected HttpContext Context { get; private set; }

        protected HttpRequest Request
        {
            get => Context.Request;
        }

        protected HttpResponse Response
        {
            get => Context.Response;
        }

        protected PathString OriginalPath => Context.Features.Get<IAuthenticationFeature>()?.OriginalPath ?? Request.Path;

        protected PathString OriginalPathBase => Context.Features.Get<IAuthenticationFeature>()?.OriginalPathBase ?? Request.PathBase;

        protected ILogger Logger { get; }

        protected UrlEncoder UrlEncoder { get; }

        protected ISystemClock Clock { get; }

        protected IOptionsMonitor<TOptions> OptionsMonitor { get; }
```

```
    /// <summary>
        /// 处理程序在事件上调用方法，这些方法在发生处理的某些点为应用程序提供控制。
         ///如果未提供，则提供默认实例，该默认实例在调用方法时不执行任何操作。
        /// </summary>
        protected virtual object Events { get; set; }

        protected virtual string ClaimsIssuer => Options.ClaimsIssuer ?? Scheme.Name;

        protected string CurrentUri
        {
            get => Request.Scheme + "://" + Request.Host + Request.PathBase + Request.Path + Request.QueryString;
        }
```
```
        protected AuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        {
            Logger = logger.CreateLogger(this.GetType().FullName);
            UrlEncoder = encoder;
            Clock = clock;
            OptionsMonitor = options;
        }
```
```
        /// <summary>
        /// 初始化处理程序，解析选项并验证它们。
        /// </summary>
        /// <param name="scheme"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
        {
            if (scheme == null)
            {
                throw new ArgumentNullException(nameof(scheme));
            }
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Scheme = scheme;
            Context = context;

            Options = OptionsMonitor.Get(Scheme.Name);

            await InitializeEventsAsync();
            await InitializeHandlerAsync();
        }

                /// <summary>
        /// 初始化事件对象，每个请求由<see cref =“ InitializeAsync（AuthenticationScheme，HttpContext）” />调用一次。
        /// </summary>
        protected virtual async Task InitializeEventsAsync()
        {
            Events = Options.Events;
            if (Options.EventsType != null)
            {
                Events = Context.RequestServices.GetRequiredService(Options.EventsType);
            }
            Events = Events ?? await CreateEventsAsync();
        }

        /// <summary>
        /// 创建事件实例的新实例。
        /// </summary>
        /// <returns>A new instance of the events instance.</returns>
        protected virtual Task<object> CreateEventsAsync() => Task.FromResult(new object());

        /// <summary>
        /// 在选项/事件已初始化之后调用，以使处理程序完成自身的初始化。
        /// </summary>
        /// <returns>A task</returns>
        protected virtual Task InitializeHandlerAsync() => Task.CompletedTask;
```
```
        protected string BuildRedirectUri(string targetPath)
            => Request.Scheme + "://" + Request.Host + OriginalPathBase + targetPath;

        //则指定身份验证处理程序应将所有身份验证操作转发到的默认方案
         首先进行设置，然后检查ForwardDefaultSelector，再检查ForwardDefault。 第一个非空结果
         ///将用作转发到的目标方案。
        protected virtual string ResolveTarget(string scheme)
        {
            var target = scheme ?? Options.ForwardDefaultSelector?.Invoke(Context) ?? Options.ForwardDefault;

            // Prevent self targetting
            return string.Equals(target, Scheme.Name, StringComparison.Ordinal)
                ? null
                : target;
        }

        public async Task<AuthenticateResult> AuthenticateAsync()
        {
            var target = ResolveTarget(Options.ForwardAuthenticate);
            if (target != null)
            {
                return await Context.AuthenticateAsync(target);
            }

            // Calling Authenticate more than once should always return the original value.
            var result = await HandleAuthenticateOnceAsync();
            if (result?.Failure == null)
            {
                var ticket = result?.Ticket;
                if (ticket?.Principal != null)
                {
                    Logger.AuthenticationSchemeAuthenticated(Scheme.Name);
                }
                else
                {
                    Logger.AuthenticationSchemeNotAuthenticated(Scheme.Name);
                }
            }
            else
            {
                Logger.AuthenticationSchemeNotAuthenticatedWithFailure(Scheme.Name, result.Failure.Message);
            }
            return result;
        }
```
```
  /// <summary>
        /// 用于确保HandleAuthenticateAsync仅被调用一次。 后续通话
         ///将返回相同的身份验证结果。
        /// </summary>
        protected Task<AuthenticateResult> HandleAuthenticateOnceAsync()
        {
            if (_authenticateTask == null)
            {
                _authenticateTask = HandleAuthenticateAsync();
            }

            return _authenticateTask;
        }

        /// <summary>
        /// 用于确保HandleAuthenticateAsync仅安全地调用一次。 后续
         ///调用将返回相同的身份验证结果。 任何异常都会被转换
         ///进入包含异常的失败身份验证结果。
        /// </summary>
        protected async Task<AuthenticateResult> HandleAuthenticateOnceSafeAsync()
        {
            try
            {
                return await HandleAuthenticateOnceAsync();
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail(ex);
            }
        }

        protected abstract Task<AuthenticateResult> HandleAuthenticateAsync();

        /// <summary>
        /// 重写此方法以处理“禁止”。
        /// </summary>
        /// <param name="properties"></param>
        /// <returns>A Task.</returns>
        protected virtual Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 403;
            return Task.CompletedTask;
        }

        /// <summary>
        /// 如果有问题的身份验证方案，则重写此方法来处理401挑战问题
         ///在其请求流中进行身份验证交互。 （例如添加响应标头，或
         ///将登录页面或外部登录位置的401结果更改为302。）
        /// </summary>
        /// <param name="properties"></param>
        /// <returns>A Task.</returns>
        protected virtual Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 401;
            return Task.CompletedTask;
        }

        public async Task ChallengeAsync(AuthenticationProperties properties)
        {
            var target = ResolveTarget(Options.ForwardChallenge);
            if (target != null)
            {
                await Context.ChallengeAsync(target, properties);
                return;
            }

            properties = properties ?? new AuthenticationProperties();
            await HandleChallengeAsync(properties);
            Logger.AuthenticationSchemeChallenged(Scheme.Name);
        }

        public async Task ForbidAsync(AuthenticationProperties properties)
        {
            var target = ResolveTarget(Options.ForwardForbid);
            if (target != null)
            {
                await Context.ForbidAsync(target, properties);
                return;
            }

            properties = properties ?? new AuthenticationProperties();
            await HandleForbiddenAsync(properties);
            Logger.AuthenticationSchemeForbidden(Scheme.Name);
        }
```
### AuthenticationMiddleware
    //认证中间件
```
 private readonly RequestDelegate _next;

        public AuthenticationMiddleware(RequestDelegate next, IAuthenticationSchemeProvider schemes)
        {
            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }
            if (schemes == null)
            {
                throw new ArgumentNullException(nameof(schemes));
            }

            _next = next;
            Schemes = schemes;
        }

              public IAuthenticationSchemeProvider Schemes { get; set; }

        public async Task Invoke(HttpContext context)
        {
            context.Features.Set<IAuthenticationFeature>(new AuthenticationFeature
            {
                OriginalPath = context.Request.Path,
                OriginalPathBase = context.Request.PathBase
            });

            // Give any IAuthenticationRequestHandler schemes a chance to handle the request
            var handlers = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
            foreach (var scheme in await Schemes.GetRequestHandlerSchemesAsync())
            {
                var handler = await handlers.GetHandlerAsync(context, scheme.Name) as IAuthenticationRequestHandler;
                if (handler != null && await handler.HandleRequestAsync())
                {
                    return;
                }
            }

            var defaultAuthenticate = await Schemes.GetDefaultAuthenticateSchemeAsync();
            if (defaultAuthenticate != null)
            {
                var result = await context.AuthenticateAsync(defaultAuthenticate.Name);
                if (result?.Principal != null)
                {
                    context.User = result.Principal;
                }
            }

            await _next(context);
        }
```
### AuthenticationSchemeOptions
    //包含由AuthenticationHandler所使用的选项
```
        /// <summary>
        /// 检查选项是否有效。 如果情况不好，应该抛出异常。
        /// </summary>
        public virtual void Validate() { }

        /// <summary>
        /// 检查选项对于特定方案是否有效
        /// </summary>
        /// <param name="scheme">The scheme being validated.</param>
        public virtual void Validate(string scheme)
            => Validate();

        /// <summary>
        /// 获取或设置应用于创建的任何声明的颁发者
        /// </summary>
        public string ClaimsIssuer { get; set; }

        /// <summary>
        /// 用于事件的实例
        /// </summary>
        public object Events { get; set; }

        /// <summary>
        ///如果设置，将用作获取事件实例
        /// </summary>
        public Type EventsType { get; set; }

        /// <summary>
        /// 如果设置，则指定身份验证处理程序应将所有身份验证操作转发到的默认方案
         /// 默认。 默认转发逻辑将检查最具体的ForwardAuthenticate / Challenge / Forbid / SignIn / SignOut
         ///首先进行设置，然后检查ForwardDefaultSelector，再检查ForwardDefault。 第一个非空结果
         ///将用作转发到的目标方案。
        /// </summary>
        public string ForwardDefault { get; set; }

        /// <summary>
        /// 如果设置，则指定此方案应将AuthenticateAsync调用转发到的目标方案。
         ///例如Context.AuthenticateAsync（“ ThisScheme”）=> Context.AuthenticateAsync（“ ForwardAuthenticateValue”）;
         ///将目标设置为当前方案以禁用转发并允许正常处理。
        /// </summary>
        public string ForwardAuthenticate { get; set; }

        /// <summary>
        /// 如果设置，则指定该方案应将ChallengeAsync调用转发到的目标方案。
         ///例如Context.ChallengeAsync（“ ThisScheme”）=> Context.ChallengeAsync（“ ForwardChallengeValue”）;
         ///将目标设置为当前方案以禁用转发并允许正常处理。
        /// </summary>
        public string ForwardChallenge { get; set; }

        /// <summary>
        /// 如果设置，则指定该方案应将ForbidAsync调用转发到的目标方案。
         ///例如Context.ForbidAsync（“ ThisScheme”）=> Context.ForbidAsync（“ ForwardForbidValue”）;
         ///将目标设置为当前方案以禁用转发并允许正常处理。
        /// </summary>
        public string ForwardForbid { get; set; }

        /// <summary>
        /// 如果设置，则指定此方案应将SignInAsync调用转发到的目标方案。
         ///例如Context.SignInAsync（“ ThisScheme”）=> Context.SignInAsync（“ ForwardSignInValue”）;
         ///将目标设置为当前方案以禁用转发并允许正常处理。
        /// </summary>
        public string ForwardSignIn { get; set; }

        /// <summary>
        /// 如果设置，则指定此方案应将SignOutAsync调用转发到的目标方案。
         ///例如Context.SignOutAsync（“ ThisScheme”）=> Context.SignOutAsync（“ ForwardSignOutValue”）;
         ///将目标设置为当前方案以禁用转发并允许正常处理。
        /// </summary>
        public string ForwardSignOut { get; set; }

        /// <summary>
        /// 用于为当前请求选择默认方案，身份验证处理程序应将所有身份验证操作转发给该默认方案
         /// 默认。 默认转发逻辑将检查最具体的ForwardAuthenticate / Challenge / Forbid / SignIn / SignOut
         ///首先进行设置，然后检查ForwardDefaultSelector，再检查ForwardDefault。 第一个非空结果
         ///将用作转发到的目标方案。
        /// </summary>
        public Func<HttpContext, string> ForwardDefaultSelector { get; set; }
```
### AuthenticationServiceCollectionExtensions
    //在<see cref =“ IServiceCollection” />中设置身份验证服务的扩展方法。
```
        public static AuthenticationBuilder AddAuthentication(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddAuthenticationCore();
            services.AddDataProtection();
            services.AddWebEncoders();
            services.TryAddSingleton<ISystemClock, SystemClock>();
            return new AuthenticationBuilder(services);
        }

        public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, string defaultScheme)
            => services.AddAuthentication(o => o.DefaultScheme = defaultScheme);

        public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, Action<AuthenticationOptions> configureOptions) {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            var builder = services.AddAuthentication();
            services.Configure(configureOptions);
            return builder;
        }

        //用于确保始终存在登录方案
        private class EnsureSignInScheme<TOptions> : IPostConfigureOptions<TOptions> where TOptions : RemoteAuthenticationOptions
        {
            private readonly AuthenticationOptions _authOptions;

            public EnsureSignInScheme(IOptions<AuthenticationOptions> authOptions)
            {
                _authOptions = authOptions.Value;
            }

            public void PostConfigure(string name, TOptions options)
            {
                options.SignInScheme = options.SignInScheme ?? _authOptions.DefaultSignInScheme;
            }
        }
```
### HandleRequestResult
    //包含验证调用的结果
```
       /// <summary>
        /// 表示身份验证阶段是直接由
         ///用户干预，不应尝试进一步处理。
        /// </summary>
        public bool Handled { get; private set; }

        /// <summary>
        /// 指示默认身份验证逻辑应为
         ///跳过，应调用其余的管道。
        /// </summary>
        public bool Skipped { get; private set; }

        /// <summary>
        /// 表示认证成功。
        /// </summary>
        /// <param name="ticket">The ticket representing the authentication result.</param>
        /// <returns>The result.</returns>
        public static new HandleRequestResult Success(AuthenticationTicket ticket)
        {
            if (ticket == null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }
            return new HandleRequestResult() { Ticket = ticket, Properties = ticket.Properties };
        }

        /// <summary>
        /// 指示认证期间失败。
        /// </summary>
        /// <param name="failure">The failure exception.</param>
        /// <returns>The result.</returns>
        public static new HandleRequestResult Fail(Exception failure)
        {
            return new HandleRequestResult() { Failure = failure };
        }

        /// <summary>
        /// 指示认证期间失败。
        /// </summary>
        /// <param name="failure">The failure exception.</param>
        /// <param name="properties">Additional state values for the authentication session.</param>
        /// <returns>The result.</returns>
        public static new HandleRequestResult Fail(Exception failure, AuthenticationProperties properties)
        {
            return new HandleRequestResult() { Failure = failure, Properties = properties };
        }

        /// <summary>
        /// 指示认证期间失败。
        /// </summary>
        /// <param name="failureMessage">The failure message.</param>
        /// <returns>The result.</returns>
        public static new HandleRequestResult Fail(string failureMessage)
            => Fail(new Exception(failureMessage));

        /// <summary>
        /// 指示认证期间失败。
        /// </summary>
        /// <param name="failureMessage">The failure message.</param>
        /// <param name="properties">Additional state values for the authentication session.</param>
        /// <returns>The result.</returns>
        public static new HandleRequestResult Fail(string failureMessage, AuthenticationProperties properties)
            => Fail(new Exception(failureMessage), properties);

        /// <summary>
        /// 停止对此请求的所有处理，然后返回到客户端。
         ///调用方负责生成完整的响应。
        /// </summary>
        /// <returns>The result.</returns>
        public static HandleRequestResult Handle()
        {
            return new HandleRequestResult() { Handled = true };
        }

        /// <summary>
        /// 在当前处理程序中停止处理请求。
        /// </summary>
        /// <returns>The result.</returns>
        public static HandleRequestResult SkipHandler()
        {
            return new HandleRequestResult() { Skipped = true };
        }

        public new static HandleRequestResult NoResult()
        {
            return new HandleRequestResult() { None = true };
        }
```
### PolicySchemeHandler
    //PolicySchemes用于将身份验证方法重定向到另一个方案。
```
        public PolicySchemeHandler(IOptionsMonitor<PolicySchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        { }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
            => throw new NotImplementedException();

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
            => throw new NotImplementedException();

        protected override Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
            => throw new NotImplementedException();

        protected override Task HandleSignOutAsync(AuthenticationProperties properties)
            => throw new NotImplementedException();

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => throw new NotImplementedException();
```
```
  public class PolicySchemeOptions : AuthenticationSchemeOptions
    { }
```
### RemoteAuthenticationHandler
```
        private const string CorrelationProperty = ".xsrf";
        private const string CorrelationMarker = "N";
        private const string AuthSchemeKey = ".AuthScheme";

        private static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();

        protected string SignInScheme => Options.SignInScheme;
```
```
        /// <summary>
        /// 处理程序在事件上调用方法，这些方法在发生处理的某些点为应用程序提供控制。
         ///如果未提供，则提供默认实例，该默认实例在调用方法时不执行任何操作。
        /// </summary>
        protected new RemoteAuthenticationEvents Events
        {
            get { return (RemoteAuthenticationEvents)base.Events; }
            set { base.Events = value; }
        }

       protected RemoteAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock) { }

        protected override Task<object> CreateEventsAsync()
            => Task.FromResult<object>(new RemoteAuthenticationEvents());

        public virtual Task<bool> ShouldHandleRequestAsync()
            => Task.FromResult(Options.CallbackPath == Request.Path);
```

```
        public virtual async Task<bool> HandleRequestAsync()
        {
            if (!await ShouldHandleRequestAsync())
            {
                return false;
            }

            AuthenticationTicket ticket = null;
            Exception exception = null;
            AuthenticationProperties properties = null;
            try
            {
                var authResult = await HandleRemoteAuthenticateAsync();
                if (authResult == null)
                {
                    exception = new InvalidOperationException("Invalid return state, unable to redirect.");
                }
                else if (authResult.Handled)
                {
                    return true;
                }
                else if (authResult.Skipped || authResult.None)
                {
                    return false;
                }
                else if (!authResult.Succeeded)
                {
                    exception = authResult.Failure ?? new InvalidOperationException("Invalid return state, unable to redirect.");
                    properties = authResult.Properties;
                }

                ticket = authResult?.Ticket;
            }
            catch (Exception ex)
            {
                exception = ex;
            }

            if (exception != null)
            {
                Logger.RemoteAuthenticationError(exception.Message);
                var errorContext = new RemoteFailureContext(Context, Scheme, Options, exception)
                {
                    Properties = properties
                };
                await Events.RemoteFailure(errorContext);

                if (errorContext.Result != null)
                {
                    if (errorContext.Result.Handled)
                    {
                        return true;
                    }
                    else if (errorContext.Result.Skipped)
                    {
                        return false;
                    }
                    else if (errorContext.Result.Failure != null)
                    {
                        throw new Exception("An error was returned from the RemoteFailure event.", errorContext.Result.Failure);
                    }
                }

                if (errorContext.Failure != null)
                {
                    throw new Exception("An error was encountered while handling the remote login.", errorContext.Failure);
                }
            }

            // 如果我们到这里，我们有票据
            var ticketContext = new TicketReceivedContext(Context, Scheme, Options, ticket)
            {
                ReturnUri = ticket.Properties.RedirectUri
            };

            ticket.Properties.RedirectUri = null;

            // 标记哪个提供商产生了此身份，以便我们稍后可以在HandleAuthenticateAsync中进行交叉检查
            ticketContext.Properties.Items[AuthSchemeKey] = Scheme.Name;

            await Events.TicketReceived(ticketContext);

            if (ticketContext.Result != null)
            {
                if (ticketContext.Result.Handled)
                {
                    Logger.SignInHandled();
                    return true;
                }
                else if (ticketContext.Result.Skipped)
                {
                    Logger.SignInSkipped();
                    return false;
                }
            }

            await Context.SignInAsync(SignInScheme, ticketContext.Principal, ticketContext.Properties);

            // Default redirect path is the base path
            if (string.IsNullOrEmpty(ticketContext.ReturnUri))
            {
                ticketContext.ReturnUri = "/";
            }

            Response.Redirect(ticketContext.ReturnUri);
            return true;
        }
```
### RemoteAuthenticationOptions
    //RemoteAuthenticationOptions : AuthenticationSchemeOptions
    //包含<see cref =“ RemoteAuthenticationHandler {T}” />所使用的选项。
```
        private const string CorrelationPrefix = ".AspNetCore.Correlation.";

        private CookieBuilder _correlationCookieBuilder;
```
```
        /// <summary>
        /// Initializes a new <see cref="RemoteAuthenticationOptions"/>.
        /// </summary>
        public RemoteAuthenticationOptions()
        {
            _correlationCookieBuilder = new CorrelationCookieBuilder(this)
            {
                Name = CorrelationPrefix,
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                SecurePolicy = CookieSecurePolicy.SameAsRequest,
                IsEssential = true,
            };
        }

        /// <summary>
        /// 检查选项对于特定方案是否有效
        /// </summary>
        /// <param name="scheme">The scheme being validated.</param>
        public override void Validate(string scheme)
        {
            base.Validate(scheme);
            if (string.Equals(scheme, SignInScheme, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(Resources.Exception_RemoteSignInSchemeCannotBeSelf);
            }
        }

        /// <summary>
        /// 检查选项是否有效。 如果情况不好，应该抛出异常。
        /// </summary>
        public override void Validate()
        {
            base.Validate();
            if (CallbackPath == null || !CallbackPath.HasValue)
            {
                throw new ArgumentException(Resources.FormatException_OptionMustBeProvided(nameof(CallbackPath)), nameof(CallbackPath));
            }
        }
```
```
       /// <summary>
        /// 获取或设置与远程身份提供者进行反向通道通信的超时值（以毫秒为单位）。
        /// </summary>
        /// <value>
        /// The back channel timeout.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>
        /// HttpMessageHandler用于与远程身份提供者进行通信。
         ///除非该值不能与BackchannelCertificateValidator同时设置
         ///可以向下转换到WebRequestHandler。
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///用于与远程身份提供者进行通信。
        /// </summary>
        public HttpClient Backchannel { get; set; }

        /// <summary>
        /// 获取或设置用于保护数据的类型。
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }

        /// <summary>
        /// 应用程序基本路径中将返回用户代理的请求路径。
         ///中间件将在请求到达时对其进行处理。
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// 获取或设置如果用户将用户代理重定向到的可选路径
         ///不批准远程服务器请求的授权需求。
         ///默认情况下未设置此属性。 在这种情况下，将引发异常
         ///如果远程授权服务器返回了access_denied响应。
        /// </summary>
        public PathString AccessDeniedPath { get; set; }

        /// <summary>
        ///获取或设置用于传达原始位置的参数的名称
         ///在触发远程质询之前直至访问拒绝页面的用户。
         ///仅在显式指定<see cref =“ AccessDeniedPath” />时使用此属性。
        /// </summary>
        // Note: this deliberately matches the default parameter name used by the cookie handler.
        public string ReturnUrlParameter { get; set; } = "ReturnUrl";

        /// <summary>
        ///获取或设置与中间件相对应的身份验证方案
         ///负责在成功通过身份验证后保留用户的身份。
         ///该值通常对应于在Startup类中注册的cookie中间件。
         ///如果省略，则将<see cref =“ AuthenticationOptions.DefaultSignInScheme” />用作后备值。
        /// </summary>
        public string SignInScheme { get; set; }

        /// <summary>
        /// 获取或设置完成身份验证流程的时间限制（默认为15分钟）。
        /// </summary>
        public TimeSpan RemoteAuthenticationTimeout { get; set; } = TimeSpan.FromMinutes(15);

        public new RemoteAuthenticationEvents Events
        {
            get => (RemoteAuthenticationEvents)base.Events;
            set => base.Events = value;
        }

        /// <summary>
        /// 定义是否将访问令牌和刷新令牌存储在
         /// <成功后，请参见cref =“ AuthenticationProperties” />。
         ///此属性默认设置为<c> false </ c>以减少
         ///最终身份验证Cookie的大小。
        /// </summary>
        public bool SaveTokens { get; set; }

        /// <summary>
        /// 确定用于在创建关联Cookie之前设置的设置
         /// cookie被添加到响应中。
        /// </summary>
        public CookieBuilder CorrelationCookie
        {
            get => _correlationCookieBuilder;
            set => _correlationCookieBuilder = value ?? throw new ArgumentNullException(nameof(value));
        }
```
```
        private class CorrelationCookieBuilder : RequestPathBaseCookieBuilder
        {
            private readonly RemoteAuthenticationOptions _options;

            public CorrelationCookieBuilder(RemoteAuthenticationOptions remoteAuthenticationOptions)
            {
                _options = remoteAuthenticationOptions;
            }

            protected override string AdditionalPath => _options.CallbackPath;

            public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
            {
                var cookieOptions = base.Build(context, expiresFrom);

                if (!Expiration.HasValue || !cookieOptions.Expires.HasValue)
                {
                    cookieOptions.Expires = expiresFrom.Add(_options.RemoteAuthenticationTimeout);
                }

                return cookieOptions;
            }
        }
```
### RequestPathBaseCookieBuilder
     //Cookie生成器，用于将<see cref =“ CookieOptions.Path” />设置为请求路径库。
```
        /// <summary>
        ///获取附加到请求路径库的可选值。
        /// </summary>
        protected virtual string AdditionalPath { get; }

        public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
        {
            // 检查用户是否覆盖路径的默认值。 如果是这样，请使用该值代替我们的默认值。
            var path = Path;
            if (path == null)
            {
                var originalPathBase = context.Features.Get<IAuthenticationFeature>()?.OriginalPathBase ?? context.Request.PathBase;
                path = originalPathBase + AdditionalPath;
            }

            var options = base.Build(context, expiresFrom);

            options.Path = !string.IsNullOrEmpty(path)
                ? path
                : "/";

            return options;
        }
```
### SignInAuthenticationHandler
    //增加了对SignInAsync的支持
```
    /// <summary>
    ///增加了对SignInAsync的支持
    /// </summary>
    public abstract class SignInAuthenticationHandler<TOptions> : SignOutAuthenticationHandler<TOptions>, IAuthenticationSignInHandler
        where TOptions : AuthenticationSchemeOptions, new()
    {
        public SignInAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        { }

        public virtual Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
        {
            var target = ResolveTarget(Options.ForwardSignIn);
            return (target != null)
                ? Context.SignInAsync(target, user, properties)
                : HandleSignInAsync(user, properties ?? new AuthenticationProperties());
        }

        /// <summary>
        /// Override this method to handle SignIn.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="properties"></param>
        /// <returns>A Task.</returns>
        protected abstract Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties properties);

    }
```
### SignOutAuthenticationHandler
     //添加对SignOutAsync的支持
```
   public abstract class SignOutAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions>, IAuthenticationSignOutHandler
        where TOptions : AuthenticationSchemeOptions, new()
    {
        public SignOutAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        { }

        public virtual Task SignOutAsync(AuthenticationProperties properties)
        {
            var target = ResolveTarget(Options.ForwardSignOut);
            return (target != null)
                ? Context.SignOutAsync(target, properties)
                : HandleSignOutAsync(properties ?? new AuthenticationProperties());
        }

        /// <summary>
        /// Override this method to handle SignOut.
        /// </summary>
        /// <param name="properties"></param>
        /// <returns>A Task.</returns>
        protected abstract Task HandleSignOutAsync(AuthenticationProperties properties);
    }
```