|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AuthenticationFailedContext](#authenticationfailedcontext)
* [ForbiddenContext](#forbiddencontext)
* [JwtBearerChallengeContext](#jwtbearerchallengecontext)
* [JwtBearerDefaults](#jwtbearerdefaults)
* [JwtBearerEvents](#jwtbearerevents)
* [JwtBearerExtensions](#jwtbearerextensions)
* [JwtBearerHandler](#jwtbearerhandler)
* [JwtBearerOptions](#jwtbeareroptions)
* [JwtBearerPostConfigureOptions](#jwtnearerpostconfigureoptions)
* [MessageReceivedContext](#messagereceivedcontext)
* [TokenValidatedContext](#tokenvalidatedcontext)

### AuthenticationFailedContext
```
    public class AuthenticationFailedContext : ResultContext<JwtBearerOptions>
    {
        public AuthenticationFailedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            JwtBearerOptions options)
            : base(context, scheme, options) { }

        public Exception Exception { get; set; }
    }
```
### ForbiddenContext
```
    public class ForbiddenContext : ResultContext<JwtBearerOptions>
    {
        public ForbiddenContext(
            HttpContext context,
            AuthenticationScheme scheme,
            JwtBearerOptions options)
            : base(context, scheme, options) { }
    }
```
### JwtBearerChallengeContext
```
    public class JwtBearerChallengeContext : PropertiesContext<JwtBearerOptions>
    {
        public JwtBearerChallengeContext(
            HttpContext context,
            AuthenticationScheme scheme,
            JwtBearerOptions options,
            AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }

        /// <summary>
        /// 身份验证过程中遇到的任何故障。
        /// </summary>
        public Exception AuthenticateFailure { get; set; }

        /// <summary>
        /// 获取或设置作为一部分返回给调用者的“错误”值
         /// WWW-Authenticate标头。 该属性在以下情况下可以为null
         /// <参见cref =“ JwtBearerOptions.IncludeErrorDetails” />设置为<c> false </ c>。
        /// </summary>
        public string Error { get; set; }

        /// <summary>
        ///获取或设置作为一部分返回给调用者的“ error_description”值
         /// WWW-Authenticate标头。 该属性在以下情况下可以为null
         /// <参见cref =“ JwtBearerOptions.IncludeErrorDetails” />设置为<c> false </ c>。
        /// </summary>
        public string ErrorDescription { get; set; }

        /// <summary>
        /// 获取或设置作为的一部分返回给调用者的“ error_uri”值
         /// WWW-Authenticate标头。 除非明确设置，否则此属性始终为null。
        /// </summary>
        public string ErrorUri { get; set; }

        /// <summary>
        /// 如果为true，则将跳过此Challenge的任何默认逻辑。
        /// </summary>
        public bool Handled { get; private set; }

        /// <summary>
        /// 跳过此Challenge的任何默认逻辑。
        /// </summary>
        public void HandleResponse() => Handled = true;
    }
```
### JwtBearerDefaults
```
    /// <summary>
    ///承载身份验证使用的默认值。
    /// </summary>
    public static class JwtBearerDefaults
    {
        /// <summary>
        ///JwtBearerAuthenticationOptions中AuthenticationScheme属性的默认值
        /// </summary>
        public const string AuthenticationScheme = "Bearer";
    }
```
### JwtBearerEvents
```
    /// <summary>
    ///指定<see cref =“ JwtBearerHandler” />调用的事件，以使开发人员能够控制身份验证过程。
    /// </summary>
    public class JwtBearerEvents
    {
        /// <summary>
        /// 在请求处理期间引发异常时调用。 除非抑制，否则此事件之后将重新引发异常。
        /// </summary>
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        ///如果授权失败并导致禁止响应，则调用
        /// </summary>
        public Func<ForbiddenContext, Task> OnForbidden { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// 在首次接收到协议消息时调用。
        /// </summary>
        public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// 在安全令牌通过验证并已生成ClaimsIdentity之后调用。
        /// </summary>
        public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// 在将质询发送回呼叫者之前调用。
        /// </summary>
        public Func<JwtBearerChallengeContext, Task> OnChallenge { get; set; } = context => Task.CompletedTask;

        public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        public virtual Task Forbidden(ForbiddenContext context) => OnForbidden(context);

        public virtual Task MessageReceived(MessageReceivedContext context) => OnMessageReceived(context);

        public virtual Task TokenValidated(TokenValidatedContext context) => OnTokenValidated(context);

        public virtual Task Challenge(JwtBearerChallengeContext context) => OnChallenge(context);
    }
```
### JwtBearerExtensions
```
    public static class JwtBearerExtensions
    {
        public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder)
            => builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, Action<JwtBearerOptions> configureOptions)
            => builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtBearerOptions> configureOptions)
            => builder.AddJwtBearer(authenticationScheme, displayName: null, configureOptions: configureOptions);

        public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<JwtBearerOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerPostConfigureOptions>());
            return builder.AddScheme<JwtBearerOptions, JwtBearerHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
```
### JwtBearerHandler
```
    public class JwtBearerHandler : AuthenticationHandler<JwtBearerOptions>
    {
        private OpenIdConnectConfiguration _configuration;

        public JwtBearerHandler(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        { }

        /// <summary>
        /// 处理程序在事件上调用方法，这些方法在发生处理的某些点为应用程序提供控制。
         ///如果未提供，则提供默认实例，该默认实例在调用方法时不执行任何操作。
        /// </summary>
        protected new JwtBearerEvents Events
        {
            get => (JwtBearerEvents)base.Events;
            set => base.Events = value;
        }

        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new JwtBearerEvents());

        /// <summary>
        /// 在“授权”标头中搜索“承载”令牌。 如果找到了“ Bearer”令牌，则使用选项中设置的<see cref =“ TokenValidationParameters” />进行验证。
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string token = null;
            try
            {
                //给应用程序机会从其他位置查找，调整或拒绝令牌
                var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);

                //事件可以设置令牌
                await Events.MessageReceived(messageReceivedContext);
                if (messageReceivedContext.Result != null)
                {
                    return messageReceivedContext.Result;
                }

                //如果应用程序从其他地方检索到令牌，请使用该令牌。
                token = messageReceivedContext.Token;

                if (string.IsNullOrEmpty(token))
                {
                    string authorization = Request.Headers[HeaderNames.Authorization];

                    //如果未找到授权标头，则无需进一步处理
                    if (string.IsNullOrEmpty(authorization))
                    {
                        return AuthenticateResult.NoResult();
                    }

                    if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        token = authorization.Substring("Bearer ".Length).Trim();
                    }

                    //如果找不到令牌，则无法进行进一步的工作
                    if (string.IsNullOrEmpty(token))
                    {
                        return AuthenticateResult.NoResult();
                    }
                }

                if (_configuration == null && Options.ConfigurationManager != null)
                {
                    _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
                }

                var validationParameters = Options.TokenValidationParameters.Clone();
                if (_configuration != null)
                {
                    var issuers = new[] { _configuration.Issuer };
                    validationParameters.ValidIssuers = validationParameters.ValidIssuers?.Concat(issuers) ?? issuers;

                    validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(_configuration.SigningKeys)
                        ?? _configuration.SigningKeys;
                }

                List<Exception> validationFailures = null;
                SecurityToken validatedToken;
                foreach (var validator in Options.SecurityTokenValidators)
                {
                    if (validator.CanReadToken(token))
                    {
                        ClaimsPrincipal principal;
                        try
                        {
                            principal = validator.ValidateToken(token, validationParameters, out validatedToken);
                        }
                        catch (Exception ex)
                        {
                            Logger.TokenValidationFailed(ex);

                            //刷新配置以获取可能由于密钥翻转而导致的异常。 用户还可以在事件中请求刷新。
                            if (Options.RefreshOnIssuerKeyNotFound && Options.ConfigurationManager != null
                                && ex is SecurityTokenSignatureKeyNotFoundException)
                            {
                                Options.ConfigurationManager.RequestRefresh();
                            }

                            if (validationFailures == null)
                            {
                                validationFailures = new List<Exception>(1);
                            }
                            validationFailures.Add(ex);
                            continue;
                        }

                        Logger.TokenValidationSucceeded();

                        var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
                        {
                            Principal = principal,
                            SecurityToken = validatedToken
                        };

                        await Events.TokenValidated(tokenValidatedContext);
                        if (tokenValidatedContext.Result != null)
                        {
                            return tokenValidatedContext.Result;
                        }

                        if (Options.SaveToken)
                        {
                            tokenValidatedContext.Properties.StoreTokens(new[]
                            {
                                new AuthenticationToken { Name = "access_token", Value = token }
                            });
                        }

                        tokenValidatedContext.Success();
                        return tokenValidatedContext.Result;
                    }
                }

                if (validationFailures != null)
                {
                    var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                    {
                        Exception = (validationFailures.Count == 1) ? validationFailures[0] : new AggregateException(validationFailures)
                    };

                    await Events.AuthenticationFailed(authenticationFailedContext);
                    if (authenticationFailedContext.Result != null)
                    {
                        return authenticationFailedContext.Result;
                    }

                    return AuthenticateResult.Fail(authenticationFailedContext.Exception);
                }

                return AuthenticateResult.Fail("No SecurityTokenValidator available for token: " + token ?? "[null]");
            }
            catch (Exception ex)
            {
                Logger.ErrorProcessingMessage(ex);

                var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = ex
                };

                await Events.AuthenticationFailed(authenticationFailedContext);
                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                throw;
            }
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            var authResult = await HandleAuthenticateOnceSafeAsync();
            var eventContext = new JwtBearerChallengeContext(Context, Scheme, Options, properties)
            {
                AuthenticateFailure = authResult?.Failure
            };

            //如果错误不是由身份验证失败引起的（例如缺少令牌），请避免返回error = invalid_token。
            if (Options.IncludeErrorDetails && eventContext.AuthenticateFailure != null)
            {
                eventContext.Error = "invalid_token";
                eventContext.ErrorDescription = CreateErrorDescription(eventContext.AuthenticateFailure);
            }

            await Events.Challenge(eventContext);
            if (eventContext.Handled)
            {
                return;
            }

            Response.StatusCode = 401;

            if (string.IsNullOrEmpty(eventContext.Error) &&
                string.IsNullOrEmpty(eventContext.ErrorDescription) &&
                string.IsNullOrEmpty(eventContext.ErrorUri))
            {
                Response.Headers.Append(HeaderNames.WWWAuthenticate, Options.Challenge);
            }
            else
            {
                // https://tools.ietf.org/html/rfc6750#section-3.1
                // WWW-Authenticate: Bearer realm="example", error="invalid_token", error_description="The access token expired"
                var builder = new StringBuilder(Options.Challenge);
                if (Options.Challenge.IndexOf(' ') > 0)
                {
                    // Only add a comma after the first param, if any
                    builder.Append(',');
                }
                if (!string.IsNullOrEmpty(eventContext.Error))
                {
                    builder.Append(" error=\"");
                    builder.Append(eventContext.Error);
                    builder.Append("\"");
                }
                if (!string.IsNullOrEmpty(eventContext.ErrorDescription))
                {
                    if (!string.IsNullOrEmpty(eventContext.Error))
                    {
                        builder.Append(",");
                    }

                    builder.Append(" error_description=\"");
                    builder.Append(eventContext.ErrorDescription);
                    builder.Append('\"');
                }
                if (!string.IsNullOrEmpty(eventContext.ErrorUri))
                {
                    if (!string.IsNullOrEmpty(eventContext.Error) ||
                        !string.IsNullOrEmpty(eventContext.ErrorDescription))
                    {
                        builder.Append(",");
                    }

                    builder.Append(" error_uri=\"");
                    builder.Append(eventContext.ErrorUri);
                    builder.Append('\"');
                }

                Response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());
            }
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            var forbiddenContext = new ForbiddenContext(Context, Scheme, Options);
            Response.StatusCode = 403;
            return Events.Forbidden(forbiddenContext);
        }
        
        private static string CreateErrorDescription(Exception authFailure)
        {
            IEnumerable<Exception> exceptions;
            if (authFailure is AggregateException agEx)
            {
                exceptions = agEx.InnerExceptions;
            }
            else
            {
                exceptions = new[] { authFailure };
            }

            var messages = new List<string>();

            foreach (var ex in exceptions)
            {
                // Order sensitive, some of these exceptions derive from others
                // and we want to display the most specific message possible.
                switch (ex)
                {
                    case SecurityTokenInvalidAudienceException stia:
                        messages.Add($"The audience '{stia.InvalidAudience ?? "(null)"}' is invalid");
                        break;
                    case SecurityTokenInvalidIssuerException stii:
                        messages.Add($"The issuer '{stii.InvalidIssuer ?? "(null)"}' is invalid");
                        break;
                    case SecurityTokenNoExpirationException _:
                        messages.Add("The token has no expiration");
                        break;
                    case SecurityTokenInvalidLifetimeException stil:
                        messages.Add("The token lifetime is invalid; NotBefore: "
                            + $"'{stil.NotBefore?.ToString(CultureInfo.InvariantCulture) ?? "(null)"}'"
                            + $", Expires: '{stil.Expires?.ToString(CultureInfo.InvariantCulture) ?? "(null)"}'");
                        break;
                    case SecurityTokenNotYetValidException stnyv:
                        messages.Add($"The token is not valid before '{stnyv.NotBefore.ToString(CultureInfo.InvariantCulture)}'");
                        break;
                    case SecurityTokenExpiredException ste:
                        messages.Add($"The token expired at '{ste.Expires.ToString(CultureInfo.InvariantCulture)}'");
                        break;
                    case SecurityTokenSignatureKeyNotFoundException _:
                        messages.Add("The signature key was not found");
                        break;
                    case SecurityTokenInvalidSignatureException _:
                        messages.Add("The signature is invalid");
                        break;
                }
            }

            return string.Join("; ", messages);
        }
    }
```
### JwtBearerOptions
```
    /// <summary>
    /// 选项类提供控制承载身份验证处理程序行为所需的信息
    /// </summary>
    public class JwtBearerOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        ///获取或设置元数据地址或权限是否需要HTTPS。
         ///默认值为true。 仅在开发环境中应禁用此功能。
        /// </summary>
        public bool RequireHttpsMetadata { get; set; } = true;

        /// <summary>
        /// Gets or sets the discovery endpoint for obtaining metadata
        /// </summary>
        public string MetadataAddress { get; set; }

        /// <summary>
        /// 获取或设置用于获取元数据的发现端点
        /// </summary>
        public string Authority { get; set; }

        /// <summary>
        /// 为任何接收到的OpenIdConnect令牌获取或设置一个有效的受众群体值。
         ///如果该属性为空，则将该值传递到TokenValidationParameters.ValidAudience中。
        /// </summary>
        /// <value>
        /// 任何收到的OpenIdConnect令牌的预期受众。
        /// </value>
        public string Audience { get; set; }

        /// <summary>
        /// 获取或设置要放入“ WWW-Authenticate”标头中的质询。
        /// </summary>
        public string Challenge { get; set; } = JwtBearerDefaults.AuthenticationScheme;

        /// <summary>
        /// 应用程序提供的对象，用于处理承载身份验证处理程序引发的事件。
         ///应用程序可以完全实现接口，也可以创建JwtBearerEvents的实例
         ///并仅将委托分配给它要处理的事件。
        /// </summary>
        public new JwtBearerEvents Events
        {
            get { return (JwtBearerEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// 用于检索元数据的HttpMessageHandler。
         ///除非该值不能与BackchannelCertificateValidator同时设置
         ///是一个WebRequestHandler。
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// 使用反向通道进行http调用时，获取或设置超时。
        /// </summary>
        public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        ///开发人员直接提供的配置。 如果提供，则提供MetadataAddress和Backchannel属性
         ///不会使用。 在请求处理期间，不应更新此信息。
        /// </summary>
        public OpenIdConnectConfiguration Configuration { get; set; }

        /// <summary>
        ///负责从元数据中检索，缓存和刷新配置。
         ///如果未提供，则将使用MetadataAddress和Backchannel属性创建一个。
        /// </summary>
        public IConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager { get; set; }

        /// <summary>
        /// 获取或设置在SecurityTokenSignatureKeyNotFoundException之后是否应尝试刷新元数据。 这允许自动
         ///在签名密钥翻转的情况下进行恢复。 默认情况下启用。
        /// </summary>
        public bool RefreshOnIssuerKeyNotFound { get; set; } = true;

        /// <summary>
        /// 获取用于验证访问令牌的<see cref =“ ISecurityTokenValidator” />的有序列表。
        /// </summary>
        public IList<ISecurityTokenValidator> SecurityTokenValidators { get; } = new List<ISecurityTokenValidator> { new JwtSecurityTokenHandler() };

        /// <summary>
        ///获取或设置用于验证身份令牌的参数。
        /// </summary>
        /// <remarks>Contains the types and definitions required for validating a token.</remarks>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
        public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();

        /// <summary>
        /// 定义是否将承载令牌存储在
         /// <cref =“ AuthenticationProperties” />。
        /// </summary>
        public bool SaveToken { get; set; } = true;

        /// <summary>
        /// 定义是否应将令牌验证错误返回给调用方。
         ///默认情况下启用，可以禁用此选项以防止JWT处理程序
         ///从WWW-Authenticate标头中返回错误和error_description。
        /// </summary>
        public bool IncludeErrorDetails { get; set; } = true;
    }
```
### JwtBearerPostConfigureOptions
```
    /// <summary>
    /// 用于为所有<see cref =“ JwtBearerOptions” />设置默认值。
    /// </summary>
    public class JwtBearerPostConfigureOptions : IPostConfigureOptions<JwtBearerOptions>
    {
        /// <summary>
        /// 调用以发布配置JwtBearerOptions实例。
        /// </summary>
        /// <param name="name">The name of the options instance being configured.</param>
        /// <param name="options">The options instance to configure.</param>
        public void PostConfigure(string name, JwtBearerOptions options)
        {
            if (string.IsNullOrEmpty(options.TokenValidationParameters.ValidAudience) && !string.IsNullOrEmpty(options.Audience))
            {
                options.TokenValidationParameters.ValidAudience = options.Audience;
            }

            if (options.ConfigurationManager == null)
            {
                if (options.Configuration != null)
                {
                    options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
                }
                else if (!(string.IsNullOrEmpty(options.MetadataAddress) && string.IsNullOrEmpty(options.Authority)))
                {
                    if (string.IsNullOrEmpty(options.MetadataAddress) && !string.IsNullOrEmpty(options.Authority))
                    {
                        options.MetadataAddress = options.Authority;
                        if (!options.MetadataAddress.EndsWith("/", StringComparison.Ordinal))
                        {
                            options.MetadataAddress += "/";
                        }

                        options.MetadataAddress += ".well-known/openid-configuration";
                    }

                    if (options.RequireHttpsMetadata && !options.MetadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("The MetadataAddress or Authority must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.");
                    }

                    var httpClient = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
                    httpClient.Timeout = options.BackchannelTimeout;
                    httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB

                    options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(options.MetadataAddress, new OpenIdConnectConfigurationRetriever(),
                        new HttpDocumentRetriever(httpClient) { RequireHttps = options.RequireHttpsMetadata });
                }
            }
        }
    }
```
### MessageReceivedContext
```
    public class MessageReceivedContext : ResultContext<JwtBearerOptions>
    {
        public MessageReceivedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            JwtBearerOptions options)
            : base(context, scheme, options) { }

        /// <summary>
        /// 承载令牌。 这将使应用程序有机会从备用位置检索令牌。
        /// </summary>
        public string Token { get; set; }
    }
```
### TokenValidatedContext
```
    public class TokenValidatedContext : ResultContext<JwtBearerOptions>
    {
        public TokenValidatedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            JwtBearerOptions options)
            : base(context, scheme, options) { }

        public SecurityToken SecurityToken { get; set; }
    }
```