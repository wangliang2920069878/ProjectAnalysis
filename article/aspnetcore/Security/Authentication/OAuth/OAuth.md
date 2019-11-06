|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [OAuthCreatingTicketContext](#oauthcreatingticketcontext)
* [OAuthEvents](#oauthevents)
* [OAuthChallengeProperties](#oauthchallengeproperties)
* [OAuthCodeExchangeContext](#oauthchallengeproperties)
* [OAuthConstants](#oauthchallengeproperties)
* [OAuthDefaults](#oauthchallengeproperties)
* [OAuthExtensions](#oauthchallengeproperties)
* [OAuthHandler](#oauthChallengeproperties)
* [OAuthOptions](#oauthchallengeproperties)
* [OAuthPostConfigureOptions](#oauthchallengeproperties)
* [OAuthTokenResponse](#oauthchallengeproperties)
### OAuthCreatingTicketContext
```
     /// <summary>
    ///包含有关登录会话以及用户<see cref =“ System.Security.Claims.ClaimsIdentity” />的信息。
    /// </summary>
    public class OAuthCreatingTicketContext : ResultContext<OAuthOptions>
    {
        /// <summary>
        /// Initializes a new <see cref="OAuthCreatingTicketContext"/>.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/>.</param>
        /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
        /// <param name="context">The HTTP environment.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="options">The options used by the authentication middleware.</param>
        /// <param name="backchannel">The HTTP client used by the authentication middleware</param>
        /// <param name="tokens">The tokens returned from the token endpoint.</param>
        /// <param name="user">The JSON-serialized user.</param>
        public OAuthCreatingTicketContext(
            ClaimsPrincipal principal,
            AuthenticationProperties properties,
            HttpContext context,
            AuthenticationScheme scheme,
            OAuthOptions options,
            HttpClient backchannel,
            OAuthTokenResponse tokens,
            JsonElement user)
            : base(context, scheme, options)
        {
            if (backchannel == null)
            {
                throw new ArgumentNullException(nameof(backchannel));
            }

            if (tokens == null)
            {
                throw new ArgumentNullException(nameof(tokens));
            }

            TokenResponse = tokens;
            Backchannel = backchannel;
            User = user;
            Principal = principal;
            Properties = properties;
        }

        /// <summary>
        /// 获取JSON序列化的用户或空
         /// <请参阅cref =“ JsonElement” />（如果不可用）。
        /// </summary>
        public JsonElement User { get; }

        /// <summary>
        /// 获取身份验证服务返回的令牌响应。
        /// </summary>
        public OAuthTokenResponse TokenResponse { get; }

        /// <summary>
        ///获取身份验证服务提供的访问令牌。
        /// </summary>
        public string AccessToken => TokenResponse.AccessToken;

        /// <summary>
        /// 获取身份验证服务提供的访问令牌类型。
        /// </summary>
        public string TokenType => TokenResponse.TokenType;

        /// <summary>
        /// 获取认证服务提供的刷新令牌。
        /// </summary>
        public string RefreshToken => TokenResponse.RefreshToken;

        /// <summary>
        /// 获取访问令牌的到期时间。
        /// </summary>
        public TimeSpan? ExpiresIn
        {
            get
            {
                int value;
                if (int.TryParse(TokenResponse.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                {
                    return TimeSpan.FromSeconds(value);
                }

                return null;
            }
        }

        /// <summary>
        ///获取用于与提供程序进行通信的反向通道。
        /// </summary>
        public HttpClient Backchannel { get; }

        /// <summary>
        /// 获取身份验证票证公开的主要身份。
         ///当票证为<c> null </ c>时，此属性返回<c> null </ c>。
        /// </summary>
        public ClaimsIdentity Identity => Principal?.Identity as ClaimsIdentity;

        public void RunClaimActions() => RunClaimActions(User);

        public void RunClaimActions(JsonElement userData)
        {
            foreach (var action in Options.ClaimActions)
            {
                action.Run(userData, Identity, Options.ClaimsIssuer ?? Scheme.Name);
            }
        }
    }
```
### OAuthEvents
```
   /// <summary>
    ///默认实现。
    /// </summary>
    public class OAuthEvents : RemoteAuthenticationEvents
    {
        /// <summary>
        /// 获取或设置在调用CreationTicket方法时调用的函数。
        /// </summary>
        public Func<OAuthCreatingTicketContext, Task> OnCreatingTicket { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// 获取或设置在调用RedirectToAuthorizationEndpoint方法时调用的委托。
        /// </summary>
        public Func<RedirectContext<OAuthOptions>, Task> OnRedirectToAuthorizationEndpoint { get; set; } = context =>
        {
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };

        /// <summary>
        /// 提供者成功验证用户身份后调用。
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task CreatingTicket(OAuthCreatingTicketContext context) => OnCreatingTicket(context);

        /// <summary>
        /// 当质询导致重定向以授权OAuth处理程序中的端点时调用。
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge.</param>
        public virtual Task RedirectToAuthorizationEndpoint(RedirectContext<OAuthOptions> context) => OnRedirectToAuthorizationEndpoint(context);
    }
```
### OAuthChallengeProperties
```
  public class OAuthChallengeProperties : AuthenticationProperties
    {
        /// <summary>
        /// 用于challenge 请求的“作用域”参数的参数键。
        /// </summary>
        public static readonly string ScopeKey = "scope";

        public OAuthChallengeProperties()
        { }

        public OAuthChallengeProperties(IDictionary<string, string> items)
            : base(items)
        { }

        public OAuthChallengeProperties(IDictionary<string, string> items, IDictionary<string, object> parameters)
            : base(items, parameters)
        { }

        /// <summary>
        /// 用于挑战请求的“范围”参数值。
        /// </summary>
        public ICollection<string> Scope
        {
            get => GetParameter<ICollection<string>>(ScopeKey);
            set => SetParameter(ScopeKey, value);
        }

        /// <summary>
        /// 设置“范围”参数值。
        /// </summary>
        /// <param name="scopes">List of scopes.</param>
        public virtual void SetScope(params string[] scopes)
        {
            Scope = scopes;
        }
    }
```
### OAuthCodeExchangeContext
```
    /// <summary>
    /// 包含用于执行代码交换的信息。
    /// </summary>
    public class OAuthCodeExchangeContext
    {
        /// <summary>
        /// Initializes a new <see cref="OAuthCodeExchangeContext"/>.
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
        /// <param name="code">The code returned from the authorization endpoint.</param>
        /// <param name="redirectUri">The redirect uri used in the authorization request.</param>
        public OAuthCodeExchangeContext(AuthenticationProperties properties, string code, string redirectUri)
        {
            Properties = properties;
            Code = code;
            RedirectUri = redirectUri;
        }

        /// <summary>
        /// State for the authentication flow.
        /// </summary>
        public AuthenticationProperties Properties { get; }

        /// <summary>
        /// The code returned from the authorization endpoint.
        /// </summary>
        public string Code { get; }

        /// <summary>
        /// The redirect uri used in the authorization request.
        /// </summary>
        public string RedirectUri { get; }
    }
```
### OAuthConstants
```
    /// <summary>
    /// OAuth协议中使用的常量
    /// </summary>
    public static class OAuthConstants
    {
        /// <summary>
        /// 在https://tools.ietf.org/html/rfc7636中定义的code_verifier
        /// </summary>
        public static readonly string CodeVerifierKey = "code_verifier";

        /// <summary>
        /// code_challenge defined in https://tools.ietf.org/html/rfc7636
        /// </summary>
        public static readonly string CodeChallengeKey = "code_challenge";

        /// <summary>
        /// code_challenge_method defined in https://tools.ietf.org/html/rfc7636
        /// </summary>
        public static readonly string CodeChallengeMethodKey = "code_challenge_method";

        /// <summary>
        /// S256 defined in https://tools.ietf.org/html/rfc7636
        /// </summary>
        public static readonly string CodeChallengeMethodS256 = "S256";
    }
```
### OAuthDefaults
```
    public static class OAuthDefaults
    {
        public static readonly string DisplayName = "OAuth";
    }
```
### OAuthExtensions
```
    public static class OAuthExtensions
    {
        public static AuthenticationBuilder AddOAuth(this AuthenticationBuilder builder, string authenticationScheme, Action<OAuthOptions> configureOptions)
            => builder.AddOAuth<OAuthOptions, OAuthHandler<OAuthOptions>>(authenticationScheme, configureOptions);

        public static AuthenticationBuilder AddOAuth(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<OAuthOptions> configureOptions)
            => builder.AddOAuth<OAuthOptions, OAuthHandler<OAuthOptions>>(authenticationScheme, displayName, configureOptions);

        public static AuthenticationBuilder AddOAuth<TOptions, THandler>(this AuthenticationBuilder builder, string authenticationScheme, Action<TOptions> configureOptions)
            where TOptions : OAuthOptions, new()
            where THandler : OAuthHandler<TOptions>
            => builder.AddOAuth<TOptions, THandler>(authenticationScheme, OAuthDefaults.DisplayName, configureOptions);

        public static AuthenticationBuilder AddOAuth<TOptions, THandler>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<TOptions> configureOptions)
            where TOptions : OAuthOptions, new()
            where THandler : OAuthHandler<TOptions>
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, OAuthPostConfigureOptions<TOptions, THandler>>());
            return builder.AddRemoteScheme<TOptions, THandler>(authenticationScheme, displayName, configureOptions);
        }
    }
```
### OAuthHandler
```
    public class OAuthHandler<TOptions> : RemoteAuthenticationHandler<TOptions> where TOptions : OAuthOptions, new()
    {
        private static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();
        protected HttpClient Backchannel => Options.Backchannel;

        /// <summary>
        ///处理程序在事件上调用方法，这些方法在发生处理的某些点为应用程序提供控制。
         ///如果未提供，则提供默认实例，该默认实例在调用方法时不执行任何操作。
        /// </summary>
        protected new OAuthEvents Events
        {
            get { return (OAuthEvents)base.Events; }
            set { base.Events = value; }
        }

        public OAuthHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        { }

        /// <summary>
        /// 创建事件实例的新实例。
        /// </summary>
        /// <returns>A new instance of the events instance.</returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new OAuthEvents());

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var query = Request.Query;

            var state = query["state"];
            var properties = Options.StateDataFormat.Unprotect(state);

            if (properties == null)
            {
                return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            }

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.", properties);
            }

            var error = query["error"];
            if (!StringValues.IsNullOrEmpty(error))
            {
                //注意：access_denied错误是特殊的协议错误，表明用户没有
                 //批准远程授权服务器请求的授权需求。
                 //由于这是常见的情况（不是由错误的配置引起的），
                 //拒绝的错误使用HandleAccessDeniedErrorAsync（）进行不同的处理。
                 //有关更多信息，请访问https://tools.ietf.org/html/rfc6749#section-4.1.2.1。
                var errorDescription = query["error_description"];
                var errorUri = query["error_uri"];
                if (StringValues.Equals(error, "access_denied"))
                {
                    var result = await HandleAccessDeniedErrorAsync(properties);
                    if (!result.None)
                    {
                        return result;
                    }
                    var deniedEx = new Exception("Access was denied by the resource owner or by the remote server.");
                    deniedEx.Data["error"] = error.ToString();
                    deniedEx.Data["error_description"] = errorDescription.ToString();
                    deniedEx.Data["error_uri"] = errorUri.ToString();

                    return HandleRequestResult.Fail(deniedEx, properties);
                }

                var failureMessage = new StringBuilder();
                failureMessage.Append(error);
                if (!StringValues.IsNullOrEmpty(errorDescription))
                {
                    failureMessage.Append(";Description=").Append(errorDescription);
                }
                if (!StringValues.IsNullOrEmpty(errorUri))
                {
                    failureMessage.Append(";Uri=").Append(errorUri);
                }

                var ex = new Exception(failureMessage.ToString());
                ex.Data["error"] = error.ToString();
                ex.Data["error_description"] = errorDescription.ToString();
                ex.Data["error_uri"] = errorUri.ToString();

                return HandleRequestResult.Fail(ex, properties);
            }

            var code = query["code"];

            if (StringValues.IsNullOrEmpty(code))
            {
                return HandleRequestResult.Fail("Code was not found.", properties);
            }

            var codeExchangeContext = new OAuthCodeExchangeContext(properties, code, BuildRedirectUri(Options.CallbackPath));
            ////注意：access_denied错误是特殊的协议错误，表明用户没有
                 //批准远程授权服务器请求的授权需求。
                 //由于这是常见的情况（不是由错误的配置引起的），
                 //拒绝的错误使用HandleAccessDeniedErrorAsync（）进行不同的处理。
                 //有关更多信息，请访问https://tools.ietf.org/html/rfc6749#section-4.1.2.1。
         
         // 传递参数 var tokenRequestParameters = new Dictionary<string, string>()
            {
                { "client_id", Options.ClientId },
                { "redirect_uri", context.RedirectUri },
                { "client_secret", Options.ClientSecret },
                { "code", context.Code },
                { "grant_type", "authorization_code" },
            };重Options.TokenEndpoint返回 AccessToken
            using var tokens = await ExchangeCodeAsync(codeExchangeContext);


            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error, properties);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.", properties);
            }

            var identity = new ClaimsIdentity(ClaimsIssuer);

            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>();

                authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
                }

                if (!string.IsNullOrEmpty(tokens.TokenType))
                {
                    authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
                }

                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    int value;
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    {
                        // https://www.w3.org/TR/xmlschema-2/#dateTime
                        // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                        var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken
                        {
                            Name = "expires_at",
                            Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                        });
                    }
                }

                properties.StoreTokens(authTokens);
            }
            //创建 AuthenticationTicket
            var ticket = await CreateTicketAsync(identity, properties, tokens);
            if (ticket != null)
            {
                return HandleRequestResult.Success(ticket);
            }
            else
            {
                return HandleRequestResult.Fail("Failed to retrieve user information from remote server.", properties);
            }
        }

        protected virtual async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            var tokenRequestParameters = new Dictionary<string, string>()
            {
                { "client_id", Options.ClientId },
                { "redirect_uri", context.RedirectUri },
                { "client_secret", Options.ClientSecret },
                { "code", context.Code },
                { "grant_type", "authorization_code" },
            };

            // PKCE https://tools.ietf.org/html/rfc7636#section-4.5, see BuildChallengeUrl
            if (context.Properties.Items.TryGetValue(OAuthConstants.CodeVerifierKey, out var codeVerifier))
            {
                tokenRequestParameters.Add(OAuthConstants.CodeVerifierKey, codeVerifier);
                context.Properties.Items.Remove(OAuthConstants.CodeVerifierKey);
            }

            var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;
            var response = await Backchannel.SendAsync(requestMessage, Context.RequestAborted);
            if (response.IsSuccessStatusCode)
            {
                var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                return OAuthTokenResponse.Success(payload);
            }
            else
            {
                var error = "OAuth token endpoint failure: " + await Display(response);
                return OAuthTokenResponse.Failed(new Exception(error));
            }
        }

        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();
            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers.ToString() + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
            return output.ToString();
        }

        protected virtual async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            using (var user = JsonDocument.Parse("{}"))
            {
                var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, user.RootElement);
                await Events.CreatingTicket(context);
                return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
            }
        }
        //第三方登录的第一次握手请求，参数:
            var parameters = new Dictionary<string, string>
            {
                { "client_id", Options.ClientId },
                { "scope", scope },
                { "response_type", "code" },
                { "redirect_uri", redirectUri },
            };返回code
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            var authorizationEndpoint = BuildChallengeUrl(properties, BuildRedirectUri(Options.CallbackPath));
            var redirectContext = new RedirectContext<OAuthOptions>(
                Context, Scheme, Options,
                properties, authorizationEndpoint);
            await Events.RedirectToAuthorizationEndpoint(redirectContext);

            var location = Context.Response.Headers[HeaderNames.Location];
            if (location == StringValues.Empty)
            {
                location = "(not set)";
            }
            var cookie = Context.Response.Headers[HeaderNames.SetCookie];
            if (cookie == StringValues.Empty)
            {
                cookie = "(not set)";
            }
            Logger.HandleChallenge(location, cookie);
        }

        protected virtual string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            var scopeParameter = properties.GetParameter<ICollection<string>>(OAuthChallengeProperties.ScopeKey);
            var scope = scopeParameter != null ? FormatScope(scopeParameter) : FormatScope();

            var parameters = new Dictionary<string, string>
            {
                { "client_id", Options.ClientId },
                { "scope", scope },
                { "response_type", "code" },
                { "redirect_uri", redirectUri },
            };

            if (Options.UsePkce)
            {
                var bytes = new byte[32];
                CryptoRandom.GetBytes(bytes);
                var codeVerifier = Base64UrlTextEncoder.Encode(bytes);

                // Store this for use during the code redemption.
                properties.Items.Add(OAuthConstants.CodeVerifierKey, codeVerifier);

                using var sha256 = SHA256.Create();
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);

                parameters[OAuthConstants.CodeChallengeKey] = codeChallenge;
                parameters[OAuthConstants.CodeChallengeMethodKey] = OAuthConstants.CodeChallengeMethodS256;
            }

            parameters["state"] = Options.StateDataFormat.Protect(properties);

            return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, parameters);
        }

        /// <summary>
        /// Format a list of OAuth scopes.
        /// </summary>
        /// <param name="scopes">List of scopes.</param>
        /// <returns>Formatted scopes.</returns>
        protected virtual string FormatScope(IEnumerable<string> scopes)
            => string.Join(" ", scopes); // OAuth2 3.3 space separated

        /// <summary>
        /// Format the <see cref="OAuthOptions.Scope"/> property.
        /// </summary>
        /// <returns>Formatted scopes.</returns>
        /// <remarks>Subclasses should rather override <see cref="FormatScope(IEnumerable{string})"/>.</remarks>
        protected virtual string FormatScope()
            => FormatScope(Options.Scope);
    }
```
### OAuthOptions
```
   /// <summary>
    /// 配置选项OAuth。
    /// </summary>
    public class OAuthOptions : RemoteAuthenticationOptions
    {
        public OAuthOptions()
        {
            Events = new OAuthEvents();
        }

        /// <summary>
        ///检查选项是否有效。 如果情况不好，应该抛出异常。
        /// </summary>
        public override void Validate()
        {
            base.Validate();

            if (string.IsNullOrEmpty(ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(ClientId)), nameof(ClientId));
            }

            if (string.IsNullOrEmpty(ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(ClientSecret)), nameof(ClientSecret));
            }

            if (string.IsNullOrEmpty(AuthorizationEndpoint))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(AuthorizationEndpoint)), nameof(AuthorizationEndpoint));
            }

            if (string.IsNullOrEmpty(TokenEndpoint))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(TokenEndpoint)), nameof(TokenEndpoint));
            }

            if (!CallbackPath.HasValue)
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(CallbackPath)), nameof(CallbackPath));
            }
        }

        /// <summary>
        ///获取或设置提供者分配的客户端ID。
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///获取或设置提供者分配的客户端机密。
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// 获取或设置客户端将被重定向到进行身份验证的URI。
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// 获取或设置中间件将用来交换OAuth令牌的URI。
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// 获取或设置中间件将访问以获得用户信息的URI。
         ///此值未在默认实现中使用，而是在以下项的自定义实现中使用
         /// IOAuthAuthenticationEvents.Authenticated或OAuthAuthenticationHandler.CreateTicketAsync。
        /// </summary>
        public string UserInformationEndpoint { get; set; }

        /// <summary>
        /// 获取或设置用于处理身份验证事件的<see cref =“ OAuthEvents” />。
        /// </summary>
        public new OAuthEvents Events
        {
            get { return (OAuthEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        ///声明动作的集合，用于从json用户数据中选择值并创建Claims。
        /// </summary>
        public ClaimActionCollection ClaimActions { get; } = new ClaimActionCollection();

        /// <summary>
        ///获取请求的权限列表。
        /// </summary>
        public ICollection<string> Scope { get; } = new HashSet<string>();

        /// <summary>
        ///获取或设置用于保护中间件处理的数据的类型。
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// 启用或禁用对代码交换证明密钥（PKCE）标准的使用。 请参阅https://tools.ietf.org/html/rfc7636。
         ///默认值为false，但是派生的处理程序应该在提供程序支持的情况下启用它。
        /// </summary>
        public bool UsePkce { get; set; } = false;
    }
```
### OAuthPostConfigureOptions
```
    /// <summary>
    /// 用于设置OAuthOptions的默认值。
    /// </summary>
    public class OAuthPostConfigureOptions<TOptions, THandler> : IPostConfigureOptions<TOptions>
        where TOptions : OAuthOptions, new()
        where THandler : OAuthHandler<TOptions>
    {
        private readonly IDataProtectionProvider _dp;

        public OAuthPostConfigureOptions(IDataProtectionProvider dataProtection)
        {
            _dp = dataProtection;
        }

        public void PostConfigure(string name, TOptions options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;
            if (options.Backchannel == null)
            {
                options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
                options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft ASP.NET Core OAuth handler");
                options.Backchannel.Timeout = options.BackchannelTimeout;
                options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(THandler).FullName, name, "v1");
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
        }
    }
```
### OAuthTokenResponse
```
    public class OAuthTokenResponse : IDisposable
    {
        private OAuthTokenResponse(JsonDocument response)
        {
            Response = response;
            var root = response.RootElement;
            AccessToken = root.GetString("access_token");
            TokenType = root.GetString("token_type");
            RefreshToken = root.GetString("refresh_token");
            ExpiresIn = root.GetString("expires_in");
        }

        private OAuthTokenResponse(Exception error)
        {
            Error = error;
        }

        public static OAuthTokenResponse Success(JsonDocument response)
        {
            return new OAuthTokenResponse(response);
        }

        public static OAuthTokenResponse Failed(Exception error)
        {
            return new OAuthTokenResponse(error);
        }

        public void Dispose()
        {
            Response?.Dispose();
        }

        public JsonDocument Response { get; set; }
        public string AccessToken { get; set; }
        public string TokenType { get; set; }
        public string RefreshToken { get; set; }
        public string ExpiresIn { get; set; }
        public Exception Error { get; set; }
    }
```