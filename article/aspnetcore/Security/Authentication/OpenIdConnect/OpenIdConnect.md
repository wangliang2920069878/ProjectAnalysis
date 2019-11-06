|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AuthorizationCodeReceivedContext](#authorizationcodereceivedcontext)
* [ClaimActionCollectionUniqueExtensions](#claimactioncollectionuniqueextensions)
* [OpenIdConnectChallengeProperties](#openidconnectchallengeproperties)
* [OpenIdConnectDefaults](#openidconnectdefaults)
* [OpenIdConnectExtensions](#openidconnectextensions)
* [OpenIdConnectHandler](#openidconnecthandler)
* [OpenIdConnectOptions](#openidconnectoptions)
* [OpenIdConnectPostConfigureOptions](#openidconnectpostconfigureoptions)
* [OpenIdConnectRedirectBehavior](#openIdconnectredirectbehavior)
### AuthorizationCodeReceivedContext
```
    /// <summary>
    ///当通过OpenIdConnect协议接收到“ AuthorizationCode”时，可以使用此上下文来通知。
    /// </summary>
    public class AuthorizationCodeReceivedContext : RemoteAuthenticationContext<OpenIdConnectOptions>
    {
        /// <summary>
        /// Creates a <see cref="AuthorizationCodeReceivedContext"/>
        /// </summary>
        public AuthorizationCodeReceivedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OpenIdConnectOptions options,
            AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }

        public OpenIdConnectMessage ProtocolMessage { get; set; }

        /// <summary>
        /// 获取或设置身份验证响应中收到的<see cref =“ JwtSecurityToken” />。
        /// </summary>
        public JwtSecurityToken JwtSecurityToken { get; set; }

        /// <summary>
        /// 该请求将发送到令牌端点，并且可以自定义。
        /// </summary>
        public OpenIdConnectMessage TokenEndpointRequest { get; set; }

        /// <summary>
        /// 向身份提供者配置的通信通道，以在向令牌端点发出自定义请求时使用。
        /// </summary>
        public HttpClient Backchannel { get; internal set; }

        /// <summary>
        ///如果开发人员选择自己兑换代码，则他们可以在此处提供生成的令牌。 这是
        ///与调用HandleCodeRedemption。 如果设置，则处理程序将不会尝试兑换代码。 一个IdToken
         ///如果先前未在授权响应中收到一个，则为必填。 访问令牌是可选的
         ///如果处理程序要联系用户信息端点。
        /// </summary>
        public OpenIdConnectMessage TokenEndpointResponse { get; set; }

        /// <summary>
        /// 指示开发人员是否选择处理（或跳过）代码兑换。 如果为true，则处理程序将不会尝试
         ///兑换代码。 请参阅HandleCodeRedemption和TokenEndpointResponse。
        /// </summary>
        public bool HandledCodeRedemption => TokenEndpointResponse != null;

        /// <summary>
        ///告诉处理程序跳过代码兑换过程。 开发人员可能自己赎回了代码，或者
         ///决定不需要兑换。 如果检索到需要进一步处理的令牌，则
         ///调用允许提供令牌的重载之一。 如果以前未收到过，则需要一个IdToken
         ///在授权回应中。 可以选择提供访问令牌，供处理程序联系
         ///用户信息端点。 调用与设置TokenEndpointResponse相同。
        /// </summary>
        public void HandleCodeRedemption()
        {
            TokenEndpointResponse = new OpenIdConnectMessage();
        }

        /// <summary>
        ///告诉处理程序跳过代码兑换过程。 开发人员可能自己赎回了代码，或者
         ///决定不需要兑换。 如果检索到需要进一步处理的令牌，则
         ///调用允许提供令牌的重载之一。 如果以前未收到过，则需要一个IdToken
         ///在授权回应中。 可以选择提供访问令牌，供处理程序联系
         ///用户信息端点。 调用与设置TokenEndpointResponse相同。
        /// </summary>
        public void HandleCodeRedemption(string accessToken, string idToken)
        {
            TokenEndpointResponse = new OpenIdConnectMessage() { AccessToken = accessToken, IdToken = idToken };
        }

        /// <summary>
        /// 告诉处理程序跳过代码兑换过程。 开发人员可能自己赎回了代码，或者
         ///决定不需要兑换。 如果检索到需要进一步处理的令牌，则
         ///调用允许提供令牌的重载之一。 如果以前未收到过，则需要一个IdToken
         ///在授权回应中。 可以选择提供访问令牌，供处理程序联系
         ///用户信息端点。 调用与设置TokenEndpointResponse相同。
        /// </summary>
        public void HandleCodeRedemption(OpenIdConnectMessage tokenEndpointResponse)
        {
            TokenEndpointResponse = tokenEndpointResponse;
        }
    }
```
### ClaimActionCollectionUniqueExtensions
```
    public static class ClaimActionCollectionUniqueExtensions
    {
        /// <summary>
        ///从具有给定键名的json用户数据中选择一个顶级值，并将其添加为Claim。
         ///如果没有ClaimsIdentity已经包含具有给定ClaimType的Claim，则此操作无效。
         ///如果未找到键或值为空，则此操作无效。
        /// </summary>
        /// <param name="collection"></param>
        /// <param name="claimType">The value to use for Claim.Type when creating a Claim.</param>
        /// <param name="jsonKey">The top level key to look for in the json user data.</param>
        public static void MapUniqueJsonKey(this ClaimActionCollection collection, string claimType, string jsonKey)
        {
            collection.MapUniqueJsonKey(claimType, jsonKey, ClaimValueTypes.String);
        }

        /// <summary>
        ///从具有给定键名的json用户数据中选择一个顶级值，并将其添加为Claim。
         ///如果没有ClaimsIdentity已经包含具有给定ClaimType的Claim，则此操作无效。
         ///如果未找到键或值为空，则此操作无效。
        /// </summary>
        /// <param name="collection"></param>
        /// <param name="claimType">The value to use for Claim.Type when creating a Claim.</param>
        /// <param name="jsonKey">The top level key to look for in the json user data.</param>
        /// <param name="valueType">The value to use for Claim.ValueType when creating a Claim.</param>
        public static void MapUniqueJsonKey(this ClaimActionCollection collection, string claimType, string jsonKey, string valueType)
        {
            collection.Add(new UniqueJsonKeyClaimAction(claimType, valueType, jsonKey));
        }
    }
```
### OpenIdConnectChallengeProperties
```
    public class OpenIdConnectChallengeProperties : OAuthChallengeProperties
    {
        /// <summary>
        /// 用于质询请求的“ max_age”参数的参数关键字。
        /// </summary>
        public static readonly string MaxAgeKey = OpenIdConnectParameterNames.MaxAge;

        /// <summary>
        /// 用于询问请求的“提示”参数的参数关键字。
        /// </summary>
        public static readonly string PromptKey = OpenIdConnectParameterNames.Prompt;

        public OpenIdConnectChallengeProperties()
        { }

        public OpenIdConnectChallengeProperties(IDictionary<string, string> items)
            : base(items)
        { }

        public OpenIdConnectChallengeProperties(IDictionary<string, string> items, IDictionary<string, object> parameters)
            : base(items, parameters)
        { }

        /// <summary>
        /// 参数值“ max_age”用于质询请求。
        /// </summary>
        public TimeSpan? MaxAge
        {
            get => GetParameter<TimeSpan?>(MaxAgeKey);
            set => SetParameter(MaxAgeKey, value);
        }

        /// <summary>
        /// 用于询问请求的“提示”参数值。
        /// </summary>
        public string Prompt
        {
            get => GetParameter<string>(PromptKey);
            set => SetParameter(PromptKey, value);
        }
    }
```
### OpenIdConnectDefaults
```
    /// <summary>
    /// 与OpenIdConnect身份验证处理程序有关的默认值
    /// </summary>
    public static class OpenIdConnectDefaults
    {
        /// <summary>
        /// 用于标识openIdConnect协议消息中的状态的常数。
        /// </summary>
        public static readonly string AuthenticationPropertiesKey = "OpenIdConnect.AuthenticationProperties";

        /// <summary>
        /// 用于OpenIdConnectOptions.AuthenticationScheme的默认值。
        /// </summary>
        public const string AuthenticationScheme = "OpenIdConnect";

        /// <summary>
        /// 显示名称的默认值。
        /// </summary>
        public static readonly string DisplayName = "OpenIdConnect";

        /// <summary>
        ///Cookie中用于随机数的前缀。
        /// </summary>
        public static readonly string CookieNoncePrefix = ".AspNetCore.OpenIdConnect.Nonce.";

        /// <summary>
        /// 请求RedirectUri时使用的属性'authorizationCode'.
        /// </summary>
        public static readonly string RedirectUriForCodePropertiesKey = "OpenIdConnect.Code.RedirectUri";

        /// <summary>
        /// 用于标识AuthenticationProperty中已在“ state”参数中序列化的用户状态的常数。
        /// </summary>
        public static readonly string UserstatePropertiesKey = "OpenIdConnect.Userstate";
    }

```
### OpenIdConnectExtensions
```
    public static class OpenIdConnectExtensions
    {
        public static AuthenticationBuilder AddOpenIdConnect(this AuthenticationBuilder builder)
            => builder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddOpenIdConnect(this AuthenticationBuilder builder, Action<OpenIdConnectOptions> configureOptions)
            => builder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddOpenIdConnect(this AuthenticationBuilder builder, string authenticationScheme, Action<OpenIdConnectOptions> configureOptions)
            => builder.AddOpenIdConnect(authenticationScheme, OpenIdConnectDefaults.DisplayName, configureOptions);

        public static AuthenticationBuilder AddOpenIdConnect(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<OpenIdConnectOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, OpenIdConnectPostConfigureOptions>());
            return builder.AddRemoteScheme<OpenIdConnectOptions, OpenIdConnectHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
```
### OpenIdConnectHandler
```
    /// <summary>
    /// OpenIdConnectAuthenticationMiddleware的按请求的身份验证处理程序。
    /// </summary>
    public class OpenIdConnectHandler : RemoteAuthenticationHandler<OpenIdConnectOptions>, IAuthenticationSignOutHandler
    {
        private const string NonceProperty = "N";
        private const string HeaderValueEpocDate = "Thu, 01 Jan 1970 00:00:00 GMT";

        private static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();

        private OpenIdConnectConfiguration _configuration;

        protected HttpClient Backchannel => Options.Backchannel;

        protected HtmlEncoder HtmlEncoder { get; }

        public OpenIdConnectHandler(IOptionsMonitor<OpenIdConnectOptions> options, ILoggerFactory logger, HtmlEncoder htmlEncoder, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
            HtmlEncoder = htmlEncoder;
        }

        /// <summary>
        /// 处理程序在事件上调用方法，这些方法在发生处理的某些点为应用程序提供控制。
         ///如果未提供，则提供默认实例，该默认实例在调用方法时不执行任何操作。
        /// </summary>
        protected new OpenIdConnectEvents Events
        {
            get { return (OpenIdConnectEvents)base.Events; }
            set { base.Events = value; }
        }

        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new OpenIdConnectEvents());

        public override Task<bool> HandleRequestAsync()
        {
            if (Options.RemoteSignOutPath.HasValue && Options.RemoteSignOutPath == Request.Path)
            {
                return HandleRemoteSignOutAsync();
            }
            else if (Options.SignedOutCallbackPath.HasValue && Options.SignedOutCallbackPath == Request.Path)
            {
                //会话结束后，OpenId提供程序对回调的响应。
                return HandleSignOutCallbackAsync();
            }

            return base.HandleRequestAsync();
        }

        protected virtual async Task<bool> HandleRemoteSignOutAsync()
        {
            OpenIdConnectMessage message = null;

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                message = new OpenIdConnectMessage(Request.Query.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
            }

            // 假设：如果ContentType为“ application / x-www-form-urlencoded”，则它应该很小就可以安全地读取。
            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
              && !string.IsNullOrEmpty(Request.ContentType)
              // 可能具有媒体/类型； charset = utf-8，允许部分匹配。
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                var form = await Request.ReadFormAsync();
                message = new OpenIdConnectMessage(form.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
            }

            var remoteSignOutContext = new RemoteSignOutContext(Context, Scheme, Options, message);
            await Events.RemoteSignOut(remoteSignOutContext);

            if (remoteSignOutContext.Result != null)
            {
                if (remoteSignOutContext.Result.Handled)
                {
                    Logger.RemoteSignOutHandledResponse();
                    return true;
                }
                if (remoteSignOutContext.Result.Skipped)
                {
                    Logger.RemoteSignOutSkipped();
                    return false;
                }
                if (remoteSignOutContext.Result.Failure != null)
                {
                    throw new InvalidOperationException("An error was returned from the RemoteSignOut event.", remoteSignOutContext.Result.Failure);
                }
            }

            if (message == null)
            {
                return false;
            }

           //尝试从登录处理程序保留的身份验证票证中提取会话标识符。
             //如果找不到标识符，请跳过会话标识符检查：这可能表明
             //身份验证cookie已经清除，会话标识符由于丢失而丢失
             //外部/应用程序Cookie转换，或者标识提供程序不支持会话。
            var principal = (await Context.AuthenticateAsync(Options.SignOutScheme))?.Principal;

            var sid = principal?.FindFirst(JwtRegisteredClaimNames.Sid)?.Value;
            if (!string.IsNullOrEmpty(sid))
            {
                // 确保身份提供者发送了“ sid”参数。
                if (string.IsNullOrEmpty(message.Sid))
                {
                    Logger.RemoteSignOutSessionIdMissing();
                    return true;
                }
                // 确保“ sid”参数对应于身份验证票证中存储的“ sid”。
                if (!string.Equals(sid, message.Sid, StringComparison.Ordinal))
                {
                    Logger.RemoteSignOutSessionIdInvalid();
                    return true;
                }
            }

            var iss = principal?.FindFirst(JwtRegisteredClaimNames.Iss)?.Value;
            if (!string.IsNullOrEmpty(iss))
            {
                // 确保身份提供者发送了“ iss”参数。
                if (string.IsNullOrEmpty(message.Iss))
                {
                    Logger.RemoteSignOutIssuerMissing();
                    return true;
                }
                // 确保“ iss”参数对应于身份验证票证中存储的“ iss”。
                if (!string.Equals(iss, message.Iss, StringComparison.Ordinal))
                {
                    Logger.RemoteSignOutIssuerInvalid();
                    return true;
                }
            }

            Logger.RemoteSignOut();

            //我们已收到一个远程注销请求
            await Context.SignOutAsync(Options.SignOutScheme);
            return true;
        }

        /// <summary>
        /// 将用户重定向到身份提供者以注销
        /// </summary>
        /// <returns>A task executing the sign out procedure</returns>
        public async virtual Task SignOutAsync(AuthenticationProperties properties)
        {
            var target = ResolveTarget(Options.ForwardSignOut);
            if (target != null)
            {
                await Context.SignOutAsync(target, properties);
                return;
            }

            properties = properties ?? new AuthenticationProperties();

            Logger.EnteringOpenIdAuthenticationHandlerHandleSignOutAsync(GetType().FullName);

            if (_configuration == null && Options.ConfigurationManager != null)
            {
                _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
            }

            var message = new OpenIdConnectMessage()
            {
                EnableTelemetryParameters = !Options.DisableTelemetry,
                IssuerAddress = _configuration?.EndSessionEndpoint ?? string.Empty,

                //在将用户代理重定向到实际的注销后重定向URI之前，先重定向回SignedOutCallbackPath
                PostLogoutRedirectUri = BuildRedirectUriIfRelative(Options.SignedOutCallbackPath)
            };

            // 获取帖子重定向URI。
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = BuildRedirectUriIfRelative(Options.SignedOutRedirectUri);
                if (string.IsNullOrWhiteSpace(properties.RedirectUri))
                {
                    properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
                }
            }
            Logger.PostSignOutRedirect(properties.RedirectUri);

            // 尽可能将身份令牌附加到注销请求。
            message.IdTokenHint = await Context.GetTokenAsync(Options.SignOutScheme, OpenIdConnectParameterNames.IdToken);

            var redirectContext = new RedirectContext(Context, Scheme, Options, properties)
            {
                ProtocolMessage = message
            };

            await Events.RedirectToIdentityProviderForSignOut(redirectContext);
            if (redirectContext.Handled)
            {
                Logger.RedirectToIdentityProviderForSignOutHandledResponse();
                return;
            }

            message = redirectContext.ProtocolMessage;

            if (!string.IsNullOrEmpty(message.State))
            {
                properties.Items[OpenIdConnectDefaults.UserstatePropertiesKey] = message.State;
            }

            message.State = Options.StateDataFormat.Protect(properties);

            if (string.IsNullOrEmpty(message.IssuerAddress))
            {
                throw new InvalidOperationException("Cannot redirect to the end session endpoint, the configuration may be missing or invalid.");
            }

            if (Options.AuthenticationMethod == OpenIdConnectRedirectBehavior.RedirectGet)
            {
                var redirectUri = message.CreateLogoutRequestUrl();
                if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                {
                    Logger.InvalidLogoutQueryStringRedirectUrl(redirectUri);
                }

                Response.Redirect(redirectUri);
            }
            else if (Options.AuthenticationMethod == OpenIdConnectRedirectBehavior.FormPost)
            {
                var content = message.BuildFormPost();
                var buffer = Encoding.UTF8.GetBytes(content);

                Response.ContentLength = buffer.Length;
                Response.ContentType = "text/html;charset=UTF-8";

                // Emit Cache-Control=no-cache to prevent client caching.
                Response.Headers[HeaderNames.CacheControl] = "no-cache, no-store";
                Response.Headers[HeaderNames.Pragma] = "no-cache";
                Response.Headers[HeaderNames.Expires] = HeaderValueEpocDate;

                await Response.Body.WriteAsync(buffer, 0, buffer.Length);
            }
            else
            {
                throw new NotImplementedException($"An unsupported authentication method has been configured: {Options.AuthenticationMethod}");
            }

            Logger.AuthenticationSchemeSignedOut(Scheme.Name);
        }

        /// <summary>
        /// 会话结束后，OpenId提供程序对回调的响应。
        /// </summary>
        /// <returns>A task executing the callback procedure</returns>
        protected async virtual Task<bool> HandleSignOutCallbackAsync()
        {
            var message = new OpenIdConnectMessage(Request.Query.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
            AuthenticationProperties properties = null;
            if (!string.IsNullOrEmpty(message.State))
            {
                properties = Options.StateDataFormat.Unprotect(message.State);
            }

            var signOut = new RemoteSignOutContext(Context, Scheme, Options, message)
            {
                Properties = properties,
            };

            await Events.SignedOutCallbackRedirect(signOut);
            if (signOut.Result != null)
            {
                if (signOut.Result.Handled)
                {
                    Logger.SignOutCallbackRedirectHandledResponse();
                    return true;
                }
                if (signOut.Result.Skipped)
                {
                    Logger.SignOutCallbackRedirectSkipped();
                    return false;
                }
                if (signOut.Result.Failure != null)
                {
                    throw new InvalidOperationException("An error was returned from the SignedOutCallbackRedirect event.", signOut.Result.Failure);
                }
            }

            properties = signOut.Properties;
            if (!string.IsNullOrEmpty(properties?.RedirectUri))
            {
                Response.Redirect(properties.RedirectUri);
            }

            return true;
        }

        /// <summary>
        /// 响应401挑战。 将OpenIdConnect消息发送到“身份授权”以获取身份。
        /// </summary>
        /// <returns></returns>
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            await HandleChallengeAsyncInternal(properties);
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

        private async Task HandleChallengeAsyncInternal(AuthenticationProperties properties)
        {
            Logger.EnteringOpenIdAuthenticationHandlerHandleUnauthorizedAsync(GetType().FullName);
              //订购本地RedirectUri
             // 1. Challenge.Properties.RedirectUri
             // 2.如果未设置RedirectUri，则为CurrentUri）
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
            }
            Logger.PostAuthenticationLocalRedirect(properties.RedirectUri);

            if (_configuration == null && Options.ConfigurationManager != null)
            {
                _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
            }

            var message = new OpenIdConnectMessage
            {
                ClientId = Options.ClientId,
                EnableTelemetryParameters = !Options.DisableTelemetry,
                IssuerAddress = _configuration?.AuthorizationEndpoint ?? string.Empty,
                RedirectUri = BuildRedirectUri(Options.CallbackPath),
                Resource = Options.Resource,
                ResponseType = Options.ResponseType,
                Prompt = properties.GetParameter<string>(OpenIdConnectParameterNames.Prompt) ?? Options.Prompt,
                Scope = string.Join(" ", properties.GetParameter<ICollection<string>>(OpenIdConnectParameterNames.Scope) ?? Options.Scope),
            };

            // https://tools.ietf.org/html/rfc7636
            if (Options.UsePkce && Options.ResponseType == OpenIdConnectResponseType.Code)
            {
                var bytes = new byte[32];
                CryptoRandom.GetBytes(bytes);
                var codeVerifier = Base64UrlTextEncoder.Encode(bytes);

                // Store this for use during the code redemption. See RunAuthorizationCodeReceivedEventAsync.
                properties.Items.Add(OAuthConstants.CodeVerifierKey, codeVerifier);

                using var sha256 = SHA256.Create();
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);

                message.Parameters.Add(OAuthConstants.CodeChallengeKey, codeChallenge);
                message.Parameters.Add(OAuthConstants.CodeChallengeMethodKey, OAuthConstants.CodeChallengeMethodS256);
            }

            // Add the 'max_age' parameter to the authentication request if MaxAge is not null.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            var maxAge = properties.GetParameter<TimeSpan?>(OpenIdConnectParameterNames.MaxAge) ?? Options.MaxAge;
            if (maxAge.HasValue)
            {
                message.MaxAge = Convert.ToInt64(Math.Floor((maxAge.Value).TotalSeconds))
                    .ToString(CultureInfo.InvariantCulture);
            }

            // Omitting the response_mode parameter when it already corresponds to the default
            // response_mode used for the specified response_type is recommended by the specifications.
            // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
            if (!string.Equals(Options.ResponseType, OpenIdConnectResponseType.Code, StringComparison.Ordinal) ||
                !string.Equals(Options.ResponseMode, OpenIdConnectResponseMode.Query, StringComparison.Ordinal))
            {
                message.ResponseMode = Options.ResponseMode;
            }

            if (Options.ProtocolValidator.RequireNonce)
            {
                message.Nonce = Options.ProtocolValidator.GenerateNonce();
                WriteNonceCookie(message.Nonce);
            }

            GenerateCorrelationId(properties);

            var redirectContext = new RedirectContext(Context, Scheme, Options, properties)
            {
                ProtocolMessage = message
            };

            await Events.RedirectToIdentityProvider(redirectContext);
            if (redirectContext.Handled)
            {
                Logger.RedirectToIdentityProviderHandledResponse();
                return;
            }

            message = redirectContext.ProtocolMessage;

            if (!string.IsNullOrEmpty(message.State))
            {
                properties.Items[OpenIdConnectDefaults.UserstatePropertiesKey] = message.State;
            }

            // When redeeming a 'code' for an AccessToken, this value is needed
            properties.Items.Add(OpenIdConnectDefaults.RedirectUriForCodePropertiesKey, message.RedirectUri);

            message.State = Options.StateDataFormat.Protect(properties);

            if (string.IsNullOrEmpty(message.IssuerAddress))
            {
                throw new InvalidOperationException(
                    "Cannot redirect to the authorization endpoint, the configuration may be missing or invalid.");
            }

            if (Options.AuthenticationMethod == OpenIdConnectRedirectBehavior.RedirectGet)
            {
                var redirectUri = message.CreateAuthenticationRequestUrl();
                if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                {
                    Logger.InvalidAuthenticationRequestUrl(redirectUri);
                }

                Response.Redirect(redirectUri);
                return;
            }
            else if (Options.AuthenticationMethod == OpenIdConnectRedirectBehavior.FormPost)
            {
                var content = message.BuildFormPost();
                var buffer = Encoding.UTF8.GetBytes(content);

                Response.ContentLength = buffer.Length;
                Response.ContentType = "text/html;charset=UTF-8";

                // Emit Cache-Control=no-cache to prevent client caching.
                Response.Headers[HeaderNames.CacheControl] = "no-cache, no-store";
                Response.Headers[HeaderNames.Pragma] = "no-cache";
                Response.Headers[HeaderNames.Expires] = HeaderValueEpocDate;

                await Response.Body.WriteAsync(buffer, 0, buffer.Length);
                return;
            }

            throw new NotImplementedException($"An unsupported authentication method has been configured: {Options.AuthenticationMethod}");
        }

        /// <summary>
        /// 调用以处理传入的OpenIdConnect消息。
        /// </summary>
        /// <returns>An <see cref="HandleRequestResult"/>.</returns>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            Logger.EnteringOpenIdAuthenticationHandlerHandleRemoteAuthenticateAsync(GetType().FullName);

            OpenIdConnectMessage authorizationResponse = null;

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                authorizationResponse = new OpenIdConnectMessage(Request.Query.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));

                // response_mode=query (explicit or not) and a response_type containing id_token
                // or token are not considered as a safe combination and MUST be rejected.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security
                if (!string.IsNullOrEmpty(authorizationResponse.IdToken) || !string.IsNullOrEmpty(authorizationResponse.AccessToken))
                {
                    if (Options.SkipUnrecognizedRequests)
                    {
                        // Not for us?
                        return HandleRequestResult.SkipHandler();
                    }
                    return HandleRequestResult.Fail("An OpenID Connect response cannot contain an " +
                            "identity token or an access token when using response_mode=query");
                }
            }
            // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small.
            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
              && !string.IsNullOrEmpty(Request.ContentType)
              // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                var form = await Request.ReadFormAsync();
                authorizationResponse = new OpenIdConnectMessage(form.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
            }

            if (authorizationResponse == null)
            {
                if (Options.SkipUnrecognizedRequests)
                {
                    // Not for us?
                    return HandleRequestResult.SkipHandler();
                }
                return HandleRequestResult.Fail("No message.");
            }

            AuthenticationProperties properties = null;
            try
            {
                properties = ReadPropertiesAndClearState(authorizationResponse);

                var messageReceivedContext = await RunMessageReceivedEventAsync(authorizationResponse, properties);
                if (messageReceivedContext.Result != null)
                {
                    return messageReceivedContext.Result;
                }
                authorizationResponse = messageReceivedContext.ProtocolMessage;
                properties = messageReceivedContext.Properties;

                if (properties == null || properties.Items.Count == 0)
                {
                    // Fail if state is missing, it's required for the correlation id.
                    if (string.IsNullOrEmpty(authorizationResponse.State))
                    {
                        // This wasn't a valid OIDC message, it may not have been intended for us.
                        Logger.NullOrEmptyAuthorizationResponseState();
                        if (Options.SkipUnrecognizedRequests)
                        {
                            return HandleRequestResult.SkipHandler();
                        }
                        return HandleRequestResult.Fail(Resources.MessageStateIsNullOrEmpty);
                    }

                    properties = ReadPropertiesAndClearState(authorizationResponse);
                }

                if (properties == null)
                {
                    Logger.UnableToReadAuthorizationResponseState();
                    if (Options.SkipUnrecognizedRequests)
                    {
                        // Not for us?
                        return HandleRequestResult.SkipHandler();
                    }

                    // if state exists and we failed to 'unprotect' this is not a message we should process.
                    return HandleRequestResult.Fail(Resources.MessageStateIsInvalid);
                }

                if (!ValidateCorrelationId(properties))
                {
                    return HandleRequestResult.Fail("Correlation failed.", properties);
                }

                // if any of the error fields are set, throw error null
                if (!string.IsNullOrEmpty(authorizationResponse.Error))
                {
                    // Note: access_denied errors are special protocol errors indicating the user didn't
                    // approve the authorization demand requested by the remote authorization server.
                    // Since it's a frequent scenario (that is not caused by incorrect configuration),
                    // denied errors are handled differently using HandleAccessDeniedErrorAsync().
                    // Visit https://tools.ietf.org/html/rfc6749#section-4.1.2.1 for more information.
                    if (string.Equals(authorizationResponse.Error, "access_denied", StringComparison.Ordinal))
                    {
                        var result = await HandleAccessDeniedErrorAsync(properties);
                        if (!result.None)
                        {
                            return result;
                        }
                    }

                    return HandleRequestResult.Fail(CreateOpenIdConnectProtocolException(authorizationResponse, response: null), properties);
                }

                if (_configuration == null && Options.ConfigurationManager != null)
                {
                    Logger.UpdatingConfiguration();
                    _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
                }

                PopulateSessionProperties(authorizationResponse, properties);

                ClaimsPrincipal user = null;
                JwtSecurityToken jwt = null;
                string nonce = null;
                var validationParameters = Options.TokenValidationParameters.Clone();

                // Hybrid or Implicit flow
                if (!string.IsNullOrEmpty(authorizationResponse.IdToken))
                {
                    Logger.ReceivedIdToken();
                    user = ValidateToken(authorizationResponse.IdToken, properties, validationParameters, out jwt);

                    nonce = jwt.Payload.Nonce;
                    if (!string.IsNullOrEmpty(nonce))
                    {
                        nonce = ReadNonceCookie(nonce);
                    }

                    var tokenValidatedContext = await RunTokenValidatedEventAsync(authorizationResponse, null, user, properties, jwt, nonce);
                    if (tokenValidatedContext.Result != null)
                    {
                        return tokenValidatedContext.Result;
                    }
                    authorizationResponse = tokenValidatedContext.ProtocolMessage;
                    user = tokenValidatedContext.Principal;
                    properties = tokenValidatedContext.Properties;
                    jwt = tokenValidatedContext.SecurityToken;
                    nonce = tokenValidatedContext.Nonce;
                }

                Options.ProtocolValidator.ValidateAuthenticationResponse(new OpenIdConnectProtocolValidationContext()
                {
                    ClientId = Options.ClientId,
                    ProtocolMessage = authorizationResponse,
                    ValidatedIdToken = jwt,
                    Nonce = nonce
                });

                OpenIdConnectMessage tokenEndpointResponse = null;

                // Authorization Code or Hybrid flow
                if (!string.IsNullOrEmpty(authorizationResponse.Code))
                {
                    var authorizationCodeReceivedContext = await RunAuthorizationCodeReceivedEventAsync(authorizationResponse, user, properties, jwt);
                    if (authorizationCodeReceivedContext.Result != null)
                    {
                        return authorizationCodeReceivedContext.Result;
                    }
                    authorizationResponse = authorizationCodeReceivedContext.ProtocolMessage;
                    user = authorizationCodeReceivedContext.Principal;
                    properties = authorizationCodeReceivedContext.Properties;
                    var tokenEndpointRequest = authorizationCodeReceivedContext.TokenEndpointRequest;
                    // If the developer redeemed the code themselves...
                    tokenEndpointResponse = authorizationCodeReceivedContext.TokenEndpointResponse;
                    jwt = authorizationCodeReceivedContext.JwtSecurityToken;

                    if (!authorizationCodeReceivedContext.HandledCodeRedemption)
                    {
                        tokenEndpointResponse = await RedeemAuthorizationCodeAsync(tokenEndpointRequest);
                    }

                    var tokenResponseReceivedContext = await RunTokenResponseReceivedEventAsync(authorizationResponse, tokenEndpointResponse, user, properties);
                    if (tokenResponseReceivedContext.Result != null)
                    {
                        return tokenResponseReceivedContext.Result;
                    }

                    authorizationResponse = tokenResponseReceivedContext.ProtocolMessage;
                    tokenEndpointResponse = tokenResponseReceivedContext.TokenEndpointResponse;
                    user = tokenResponseReceivedContext.Principal;
                    properties = tokenResponseReceivedContext.Properties;

                    // no need to validate signature when token is received using "code flow" as per spec
                    // [http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation].
                    validationParameters.RequireSignedTokens = false;

                    // At least a cursory validation is required on the new IdToken, even if we've already validated the one from the authorization response.
                    // And we'll want to validate the new JWT in ValidateTokenResponse.
                    var tokenEndpointUser = ValidateToken(tokenEndpointResponse.IdToken, properties, validationParameters, out var tokenEndpointJwt);

                    // Avoid reading & deleting the nonce cookie, running the event, etc, if it was already done as part of the authorization response validation.
                    if (user == null)
                    {
                        nonce = tokenEndpointJwt.Payload.Nonce;
                        if (!string.IsNullOrEmpty(nonce))
                        {
                            nonce = ReadNonceCookie(nonce);
                        }

                        var tokenValidatedContext = await RunTokenValidatedEventAsync(authorizationResponse, tokenEndpointResponse, tokenEndpointUser, properties, tokenEndpointJwt, nonce);
                        if (tokenValidatedContext.Result != null)
                        {
                            return tokenValidatedContext.Result;
                        }
                        authorizationResponse = tokenValidatedContext.ProtocolMessage;
                        tokenEndpointResponse = tokenValidatedContext.TokenEndpointResponse;
                        user = tokenValidatedContext.Principal;
                        properties = tokenValidatedContext.Properties;
                        jwt = tokenValidatedContext.SecurityToken;
                        nonce = tokenValidatedContext.Nonce;
                    }
                    else
                    {
                        if (!string.Equals(jwt.Subject, tokenEndpointJwt.Subject, StringComparison.Ordinal))
                        {
                            throw new SecurityTokenException("The sub claim does not match in the id_token's from the authorization and token endpoints.");
                        }

                        jwt = tokenEndpointJwt;
                    }

                    // Validate the token response if it wasn't provided manually
                    if (!authorizationCodeReceivedContext.HandledCodeRedemption)
                    {
                        Options.ProtocolValidator.ValidateTokenResponse(new OpenIdConnectProtocolValidationContext()
                        {
                            ClientId = Options.ClientId,
                            ProtocolMessage = tokenEndpointResponse,
                            ValidatedIdToken = jwt,
                            Nonce = nonce
                        });
                    }
                }

                if (Options.SaveTokens)
                {
                    SaveTokens(properties, tokenEndpointResponse ?? authorizationResponse);
                }

                if (Options.GetClaimsFromUserInfoEndpoint)
                {
                    return await GetUserInformationAsync(tokenEndpointResponse ?? authorizationResponse, jwt, user, properties);
                }
                else
                {
                    using (var payload = JsonDocument.Parse("{}"))
                    {
                        var identity = (ClaimsIdentity)user.Identity;
                        foreach (var action in Options.ClaimActions)
                        {
                            action.Run(payload.RootElement, identity, ClaimsIssuer);
                        }
                    }
                }

                return HandleRequestResult.Success(new AuthenticationTicket(user, properties, Scheme.Name));
            }
            catch (Exception exception)
            {
                Logger.ExceptionProcessingMessage(exception);

                // Refresh the configuration for exceptions that may be caused by key rollovers. The user can also request a refresh in the event.
                if (Options.RefreshOnIssuerKeyNotFound && exception is SecurityTokenSignatureKeyNotFoundException)
                {
                    if (Options.ConfigurationManager != null)
                    {
                        Logger.ConfigurationManagerRequestRefreshCalled();
                        Options.ConfigurationManager.RequestRefresh();
                    }
                }

                var authenticationFailedContext = await RunAuthenticationFailedEventAsync(authorizationResponse, exception);
                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                return HandleRequestResult.Fail(exception, properties);
            }
        }

        private AuthenticationProperties ReadPropertiesAndClearState(OpenIdConnectMessage message)
        {
            AuthenticationProperties properties = null;
            if (!string.IsNullOrEmpty(message.State))
            {
                properties = Options.StateDataFormat.Unprotect(message.State);

                if (properties != null)
                {
                    // If properties can be decoded from state, clear the message state.
                    properties.Items.TryGetValue(OpenIdConnectDefaults.UserstatePropertiesKey, out var userstate);
                    message.State = userstate;
                }
            }
            return properties;
        }

        private void PopulateSessionProperties(OpenIdConnectMessage message, AuthenticationProperties properties)
        {
            if (!string.IsNullOrEmpty(message.SessionState))
            {
                properties.Items[OpenIdConnectSessionProperties.SessionState] = message.SessionState;
            }

            if (!string.IsNullOrEmpty(_configuration.CheckSessionIframe))
            {
                properties.Items[OpenIdConnectSessionProperties.CheckSessionIFrame] = _configuration.CheckSessionIframe;
            }
        }

        /// <summary>
        /// Redeems the authorization code for tokens at the token endpoint.
        /// </summary>
        /// <param name="tokenEndpointRequest">The request that will be sent to the token endpoint and is available for customization.</param>
        /// <returns>OpenIdConnect message that has tokens inside it.</returns>
        protected virtual async Task<OpenIdConnectMessage> RedeemAuthorizationCodeAsync(OpenIdConnectMessage tokenEndpointRequest)
        {
            Logger.RedeemingCodeForTokens();

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, _configuration.TokenEndpoint);
            requestMessage.Content = new FormUrlEncodedContent(tokenEndpointRequest.Parameters);

            var responseMessage = await Backchannel.SendAsync(requestMessage);

            var contentMediaType = responseMessage.Content.Headers.ContentType?.MediaType;
            if (string.IsNullOrEmpty(contentMediaType))
            {
                Logger.LogDebug($"Unexpected token response format. Status Code: {(int)responseMessage.StatusCode}. Content-Type header is missing.");
            }
            else if (!string.Equals(contentMediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogDebug($"Unexpected token response format. Status Code: {(int)responseMessage.StatusCode}. Content-Type {responseMessage.Content.Headers.ContentType}.");
            }

            // Error handling:
            // 1. If the response body can't be parsed as json, throws.
            // 2. If the response's status code is not in 2XX range, throw OpenIdConnectProtocolException. If the body is correct parsed,
            //    pass the error information from body to the exception.
            OpenIdConnectMessage message;
            try
            {
                var responseContent = await responseMessage.Content.ReadAsStringAsync();
                message = new OpenIdConnectMessage(responseContent);
            }
            catch (Exception ex)
            {
                throw new OpenIdConnectProtocolException($"Failed to parse token response body as JSON. Status Code: {(int)responseMessage.StatusCode}. Content-Type: {responseMessage.Content.Headers.ContentType}", ex);
            }

            if (!responseMessage.IsSuccessStatusCode)
            {
                throw CreateOpenIdConnectProtocolException(message, responseMessage);
            }

            return message;
        }

        /// <summary>
        /// Goes to UserInfo endpoint to retrieve additional claims and add any unique claims to the given identity.
        /// </summary>
        /// <param name="message">message that is being processed</param>
        /// <param name="jwt">The <see cref="JwtSecurityToken"/>.</param>
        /// <param name="principal">The claims principal and identities.</param>
        /// <param name="properties">The authentication properties.</param>
        /// <returns><see cref="HandleRequestResult"/> which is used to determine if the remote authentication was successful.</returns>
        protected virtual async Task<HandleRequestResult> GetUserInformationAsync(
            OpenIdConnectMessage message, JwtSecurityToken jwt,
            ClaimsPrincipal principal, AuthenticationProperties properties)
        {
            var userInfoEndpoint = _configuration?.UserInfoEndpoint;

            if (string.IsNullOrEmpty(userInfoEndpoint))
            {
                Logger.UserInfoEndpointNotSet();
                return HandleRequestResult.Success(new AuthenticationTicket(principal, properties, Scheme.Name));
            }
            if (string.IsNullOrEmpty(message.AccessToken))
            {
                Logger.AccessTokenNotAvailable();
                return HandleRequestResult.Success(new AuthenticationTicket(principal, properties, Scheme.Name));
            }
            Logger.RetrievingClaims();
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", message.AccessToken);
            var responseMessage = await Backchannel.SendAsync(requestMessage);
            responseMessage.EnsureSuccessStatusCode();
            var userInfoResponse = await responseMessage.Content.ReadAsStringAsync();

            JsonDocument user;
            var contentType = responseMessage.Content.Headers.ContentType;
            if (contentType.MediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase))
            {
                user = JsonDocument.Parse(userInfoResponse);
            }
            else if (contentType.MediaType.Equals("application/jwt", StringComparison.OrdinalIgnoreCase))
            {
                var userInfoEndpointJwt = new JwtSecurityToken(userInfoResponse);
                user = JsonDocument.Parse(userInfoEndpointJwt.Payload.SerializeToJson());
            }
            else
            {
                return HandleRequestResult.Fail("Unknown response type: " + contentType.MediaType, properties);
            }

            using (user)
            {
                var userInformationReceivedContext = await RunUserInformationReceivedEventAsync(principal, properties, message, user);
                if (userInformationReceivedContext.Result != null)
                {
                    return userInformationReceivedContext.Result;
                }
                principal = userInformationReceivedContext.Principal;
                properties = userInformationReceivedContext.Properties;
                using (var updatedUser = userInformationReceivedContext.User)
                {
                    Options.ProtocolValidator.ValidateUserInfoResponse(new OpenIdConnectProtocolValidationContext()
                    {
                        UserInfoEndpointResponse = userInfoResponse,
                        ValidatedIdToken = jwt,
                    });

                    var identity = (ClaimsIdentity)principal.Identity;

                    foreach (var action in Options.ClaimActions)
                    {
                        action.Run(user.RootElement, identity, ClaimsIssuer);
                    }
                }
            }

            return HandleRequestResult.Success(new AuthenticationTicket(principal, properties, Scheme.Name));
        }

        /// <summary>
        /// Save the tokens contained in the <see cref="OpenIdConnectMessage"/> in the <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> in which tokens are saved.</param>
        /// <param name="message">The OpenID Connect response.</param>
        private void SaveTokens(AuthenticationProperties properties, OpenIdConnectMessage message)
        {
            var tokens = new List<AuthenticationToken>();

            if (!string.IsNullOrEmpty(message.AccessToken))
            {
                tokens.Add(new AuthenticationToken { Name = OpenIdConnectParameterNames.AccessToken, Value = message.AccessToken });
            }

            if (!string.IsNullOrEmpty(message.IdToken))
            {
                tokens.Add(new AuthenticationToken { Name = OpenIdConnectParameterNames.IdToken, Value = message.IdToken });
            }

            if (!string.IsNullOrEmpty(message.RefreshToken))
            {
                tokens.Add(new AuthenticationToken { Name = OpenIdConnectParameterNames.RefreshToken, Value = message.RefreshToken });
            }

            if (!string.IsNullOrEmpty(message.TokenType))
            {
                tokens.Add(new AuthenticationToken { Name = OpenIdConnectParameterNames.TokenType, Value = message.TokenType });
            }

            if (!string.IsNullOrEmpty(message.ExpiresIn))
            {
                if (int.TryParse(message.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value))
                {
                    var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                    // https://www.w3.org/TR/xmlschema-2/#dateTime
                    // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                    tokens.Add(new AuthenticationToken { Name = "expires_at", Value = expiresAt.ToString("o", CultureInfo.InvariantCulture) });
                }
            }

            properties.StoreTokens(tokens);
        }

        /// <summary>
        /// Adds the nonce to <see cref="HttpResponse.Cookies"/>.
        /// </summary>
        /// <param name="nonce">the nonce to remember.</param>
        /// <remarks><see cref="M:IResponseCookies.Append"/> of <see cref="HttpResponse.Cookies"/> is called to add a cookie with the name: 'OpenIdConnectAuthenticationDefaults.Nonce + <see cref="M:ISecureDataFormat{TData}.Protect"/>(nonce)' of <see cref="OpenIdConnectOptions.StringDataFormat"/>.
        /// The value of the cookie is: "N".</remarks>
        private void WriteNonceCookie(string nonce)
        {
            if (string.IsNullOrEmpty(nonce))
            {
                throw new ArgumentNullException(nameof(nonce));
            }

            var cookieOptions = Options.NonceCookie.Build(Context, Clock.UtcNow);

            Response.Cookies.Append(
                Options.NonceCookie.Name + Options.StringDataFormat.Protect(nonce),
                NonceProperty,
                cookieOptions);
        }

        /// <summary>
        /// Searches <see cref="HttpRequest.Cookies"/> for a matching nonce.
        /// </summary>
        /// <param name="nonce">the nonce that we are looking for.</param>
        /// <returns>echos 'nonce' if a cookie is found that matches, null otherwise.</returns>
        /// <remarks>Examine <see cref="IRequestCookieCollection.Keys"/> of <see cref="HttpRequest.Cookies"/> that start with the prefix: 'OpenIdConnectAuthenticationDefaults.Nonce'.
        /// <see cref="M:ISecureDataFormat{TData}.Unprotect"/> of <see cref="OpenIdConnectOptions.StringDataFormat"/> is used to obtain the actual 'nonce'. If the nonce is found, then <see cref="M:IResponseCookies.Delete"/> of <see cref="HttpResponse.Cookies"/> is called.</remarks>
        private string ReadNonceCookie(string nonce)
        {
            if (nonce == null)
            {
                return null;
            }

            foreach (var nonceKey in Request.Cookies.Keys)
            {
                if (nonceKey.StartsWith(Options.NonceCookie.Name))
                {
                    try
                    {
                        var nonceDecodedValue = Options.StringDataFormat.Unprotect(nonceKey.Substring(Options.NonceCookie.Name.Length, nonceKey.Length - Options.NonceCookie.Name.Length));
                        if (nonceDecodedValue == nonce)
                        {
                            var cookieOptions = Options.NonceCookie.Build(Context, Clock.UtcNow);
                            Response.Cookies.Delete(nonceKey, cookieOptions);
                            return nonce;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.UnableToProtectNonceCookie(ex);
                    }
                }
            }

            return null;
        }

        private AuthenticationProperties GetPropertiesFromState(string state)
        {
            // assume a well formed query string: <a=b&>OpenIdConnectAuthenticationDefaults.AuthenticationPropertiesKey=kasjd;fljasldkjflksdj<&c=d>
            var startIndex = 0;
            if (string.IsNullOrEmpty(state) || (startIndex = state.IndexOf(OpenIdConnectDefaults.AuthenticationPropertiesKey, StringComparison.Ordinal)) == -1)
            {
                return null;
            }

            var authenticationIndex = startIndex + OpenIdConnectDefaults.AuthenticationPropertiesKey.Length;
            if (authenticationIndex == -1 || authenticationIndex == state.Length || state[authenticationIndex] != '=')
            {
                return null;
            }

            // scan rest of string looking for '&'
            authenticationIndex++;
            var endIndex = state.Substring(authenticationIndex, state.Length - authenticationIndex).IndexOf("&", StringComparison.Ordinal);

            // -1 => no other parameters are after the AuthenticationPropertiesKey
            if (endIndex == -1)
            {
                return Options.StateDataFormat.Unprotect(Uri.UnescapeDataString(state.Substring(authenticationIndex).Replace('+', ' ')));
            }
            else
            {
                return Options.StateDataFormat.Unprotect(Uri.UnescapeDataString(state.Substring(authenticationIndex, endIndex).Replace('+', ' ')));
            }
        }

        private async Task<MessageReceivedContext> RunMessageReceivedEventAsync(OpenIdConnectMessage message, AuthenticationProperties properties)
        {
            Logger.MessageReceived(message.BuildRedirectUrl());
            var context = new MessageReceivedContext(Context, Scheme, Options, properties)
            {
                ProtocolMessage = message,
            };

            await Events.MessageReceived(context);
            if (context.Result != null)
            {
                if (context.Result.Handled)
                {
                    Logger.MessageReceivedContextHandledResponse();
                }
                else if (context.Result.Skipped)
                {
                    Logger.MessageReceivedContextSkipped();
                }
            }

            return context;
        }

        private async Task<TokenValidatedContext> RunTokenValidatedEventAsync(OpenIdConnectMessage authorizationResponse, OpenIdConnectMessage tokenEndpointResponse, ClaimsPrincipal user, AuthenticationProperties properties, JwtSecurityToken jwt, string nonce)
        {
            var context = new TokenValidatedContext(Context, Scheme, Options, user, properties)
            {
                ProtocolMessage = authorizationResponse,
                TokenEndpointResponse = tokenEndpointResponse,
                SecurityToken = jwt,
                Nonce = nonce,
            };

            await Events.TokenValidated(context);
            if (context.Result != null)
            {
                if (context.Result.Handled)
                {
                    Logger.TokenValidatedHandledResponse();
                }
                else if (context.Result.Skipped)
                {
                    Logger.TokenValidatedSkipped();
                }
            }

            return context;
        }

        private async Task<AuthorizationCodeReceivedContext> RunAuthorizationCodeReceivedEventAsync(OpenIdConnectMessage authorizationResponse, ClaimsPrincipal user, AuthenticationProperties properties, JwtSecurityToken jwt)
        {
            Logger.AuthorizationCodeReceived();

            var tokenEndpointRequest = new OpenIdConnectMessage()
            {
                ClientId = Options.ClientId,
                ClientSecret = Options.ClientSecret,
                Code = authorizationResponse.Code,
                GrantType = OpenIdConnectGrantTypes.AuthorizationCode,
                EnableTelemetryParameters = !Options.DisableTelemetry,
                RedirectUri = properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey]
            };

            // PKCE https://tools.ietf.org/html/rfc7636#section-4.5, see HandleChallengeAsyncInternal
            if (properties.Items.TryGetValue(OAuthConstants.CodeVerifierKey, out var codeVerifier))
            {
                tokenEndpointRequest.Parameters.Add(OAuthConstants.CodeVerifierKey, codeVerifier);
                properties.Items.Remove(OAuthConstants.CodeVerifierKey);
            }

            var context = new AuthorizationCodeReceivedContext(Context, Scheme, Options, properties)
            {
                ProtocolMessage = authorizationResponse,
                TokenEndpointRequest = tokenEndpointRequest,
                Principal = user,
                JwtSecurityToken = jwt,
                Backchannel = Backchannel
            };

            await Events.AuthorizationCodeReceived(context);
            if (context.Result != null)
            {
                if (context.Result.Handled)
                {
                    Logger.AuthorizationCodeReceivedContextHandledResponse();
                }
                else if (context.Result.Skipped)
                {
                    Logger.AuthorizationCodeReceivedContextSkipped();
                }
            }

            return context;
        }

        private async Task<TokenResponseReceivedContext> RunTokenResponseReceivedEventAsync(
            OpenIdConnectMessage message,
            OpenIdConnectMessage tokenEndpointResponse,
            ClaimsPrincipal user,
            AuthenticationProperties properties)
        {
            Logger.TokenResponseReceived();
            var context = new TokenResponseReceivedContext(Context, Scheme, Options, user, properties)
            {
                ProtocolMessage = message,
                TokenEndpointResponse = tokenEndpointResponse,
            };

            await Events.TokenResponseReceived(context);
            if (context.Result != null)
            {
                if (context.Result.Handled)
                {
                    Logger.TokenResponseReceivedHandledResponse();
                }
                else if (context.Result.Skipped)
                {
                    Logger.TokenResponseReceivedSkipped();
                }
            }

            return context;
        }

        private async Task<UserInformationReceivedContext> RunUserInformationReceivedEventAsync(ClaimsPrincipal principal, AuthenticationProperties properties, OpenIdConnectMessage message, JsonDocument user)
        {
            Logger.UserInformationReceived(user.ToString());

            var context = new UserInformationReceivedContext(Context, Scheme, Options, principal, properties)
            {
                ProtocolMessage = message,
                User = user,
            };

            await Events.UserInformationReceived(context);
            if (context.Result != null)
            {
                if (context.Result.Handled)
                {
                    Logger.UserInformationReceivedHandledResponse();
                }
                else if (context.Result.Skipped)
                {
                    Logger.UserInformationReceivedSkipped();
                }
            }

            return context;
        }

        private async Task<AuthenticationFailedContext> RunAuthenticationFailedEventAsync(OpenIdConnectMessage message, Exception exception)
        {
            var context = new AuthenticationFailedContext(Context, Scheme, Options)
            {
                ProtocolMessage = message,
                Exception = exception
            };

            await Events.AuthenticationFailed(context);
            if (context.Result != null)
            {
                if (context.Result.Handled)
                {
                    Logger.AuthenticationFailedContextHandledResponse();
                }
                else if (context.Result.Skipped)
                {
                    Logger.AuthenticationFailedContextSkipped();
                }
            }

            return context;
        }

        // Note this modifies properties if Options.UseTokenLifetime
        private ClaimsPrincipal ValidateToken(string idToken, AuthenticationProperties properties, TokenValidationParameters validationParameters, out JwtSecurityToken jwt)
        {
            if (!Options.SecurityTokenValidator.CanReadToken(idToken))
            {
                Logger.UnableToReadIdToken(idToken);
                throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, Resources.UnableToValidateToken, idToken));
            }

            if (_configuration != null)
            {
                var issuer = new[] { _configuration.Issuer };
                validationParameters.ValidIssuers = validationParameters.ValidIssuers?.Concat(issuer) ?? issuer;

                validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(_configuration.SigningKeys)
                    ?? _configuration.SigningKeys;
            }

            var principal = Options.SecurityTokenValidator.ValidateToken(idToken, validationParameters, out SecurityToken validatedToken);
            jwt = validatedToken as JwtSecurityToken;
            if (jwt == null)
            {
                Logger.InvalidSecurityTokenType(validatedToken?.GetType().ToString());
                throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, Resources.ValidatedSecurityTokenNotJwt, validatedToken?.GetType()));
            }

            if (validatedToken == null)
            {
                Logger.UnableToValidateIdToken(idToken);
                throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, Resources.UnableToValidateToken, idToken));
            }

            if (Options.UseTokenLifetime)
            {
                var issued = validatedToken.ValidFrom;
                if (issued != DateTime.MinValue)
                {
                    properties.IssuedUtc = issued;
                }

                var expires = validatedToken.ValidTo;
                if (expires != DateTime.MinValue)
                {
                    properties.ExpiresUtc = expires;
                }
            }

            return principal;
        }

        /// <summary>
        /// Build a redirect path if the given path is a relative path.
        /// </summary>
        private string BuildRedirectUriIfRelative(string uri)
        {
            if (string.IsNullOrEmpty(uri))
            {
                return uri;
            }

            if (!uri.StartsWith("/", StringComparison.Ordinal))
            {
                return uri;
            }

            return BuildRedirectUri(uri);
        }

        private OpenIdConnectProtocolException CreateOpenIdConnectProtocolException(OpenIdConnectMessage message, HttpResponseMessage response)
        {
            var description = message.ErrorDescription ?? "error_description is null";
            var errorUri = message.ErrorUri ?? "error_uri is null";

            if (response != null)
            {
                Logger.ResponseErrorWithStatusCode(message.Error, description, errorUri, (int)response.StatusCode);
            }
            else
            {
                Logger.ResponseError(message.Error, description, errorUri);
            }

            var ex = new OpenIdConnectProtocolException(string.Format(
                CultureInfo.InvariantCulture,
                Resources.MessageContainsError,
                message.Error,
                description,
                errorUri));
            ex.Data["error"] = message.Error;
            ex.Data["error_description"] = description;
            ex.Data["error_uri"] = errorUri;
            return ex;
        }
    }
```