|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [ChunkingCookieManager](#chunkingcookiemanager)
* [Constants](#constants)
* [CookieAuthenticationDefaults](#cookieauthenticationdefaults)
* [CookieAuthenticationEvents](#cookieauthenticationevents)
* [CookieAuthenticationHandler](#cookieauthenticationhandler)
* [CookieAuthenticationOptions](#cookieauthenticationoptions)
* [CookieExtensions](#cookieextensions)
* [CookieSignedInContext](#cookiesignedincontext)
* [CookieSigningInContext](#cookiesigningincontext)
* [CookieSigningOutContext](#cookiesigningoutcontext)
* [CookieValidatePrincipalContext](#cookievalidateprincipalcontext)
* [ICookieManager](#icookiemanager)
* [ITicketStore](#iticketstore)
* [PostConfigureCookieAuthenticationOptions](#postconfigurecookieauthenticationoptions)

### ChunkingCookieManager
```
    /// <summary>
    /// 这处理受每个cookie长度限制的cookie。 它将长的Cookie分解为响应，然后重新组合它们
     ///来自请求。
    /// </summary>
    public class ChunkingCookieManager : ICookieManager
    {

        /// <summary>
        /// Cookie中要发送回客户端的默认最大字符大小。
        /// </summary>
        public const int DefaultChunkSize = 4050;

        private const string ChunkKeySuffix = "C";
        private const string ChunkCountPrefix = "chunks-";

        public ChunkingCookieManager()
        {
            // 最低公分母。 Safari的已知限制为最低（4093），为防万一，我们没有提供任何额外的限制。
             //参见http://browsercookielimits.x64.me/。
             //至少保留40个，以免CookiePolicy尝试添加“安全”，“ samesite = strict”和/或“ httponly”。
            ChunkSize = DefaultChunkSize;
        }

        /// <summary>
        /// 发送回客户端的cookie的最大大小。 如果Cookie超过此大小，它将被细分为多个
         /// 饼干。 将此值设置为null可禁用此行为。 默认值为4090个字符，所有字符均支持
         ///常见的浏览器。
         ///
         ///请注意，浏览器还可能会限制每个域中所有cookie的总大小以及每个域中cookie的数量。
        /// </summary>
        public int? ChunkSize { get; set; }

        /// <summary>
        /// 如果不是所有的cookie块，都可以在重新组装请求中使用。
        /// </summary>
        public bool ThrowForPartialCookies { get; set; }

        // 解析“块XX”以确定应该有多少块。
        private static int ParseChunksCount(string value)
        {
            if (value != null && value.StartsWith(ChunkCountPrefix, StringComparison.Ordinal))
            {
                var chunksCountString = value.Substring(ChunkCountPrefix.Length);
                int chunksCount;
                if (int.TryParse(chunksCountString, NumberStyles.None, CultureInfo.InvariantCulture, out chunksCount))
                {
                    return chunksCount;
                }
            }
            return 0;
        }

        /// <summary>
        /// 获取重组的cookie。 非分块的cookie通常返回。
         ///缺少大块的Cookie只会返回其“ chunks-XX”头。
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns>The reassembled cookie, if any, or null.</returns>
        public string GetRequestCookie(HttpContext context, string key)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var requestCookies = context.Request.Cookies;
            var value = requestCookies[key];
            var chunksCount = ParseChunksCount(value);
            if (chunksCount > 0)
            {
                var chunks = new string[chunksCount];
                for (var chunkId = 1; chunkId <= chunksCount; chunkId++)
                {
                    var chunk = requestCookies[key + ChunkKeySuffix + chunkId.ToString(CultureInfo.InvariantCulture)];
                    if (string.IsNullOrEmpty(chunk))
                    {
                        if (ThrowForPartialCookies)
                        {
                            var totalSize = 0;
                            for (int i = 0; i < chunkId - 1; i++)
                            {
                                totalSize += chunks[i].Length;
                            }
                            throw new FormatException(
                                string.Format(
                                    CultureInfo.CurrentCulture,
                                    "The chunked cookie is incomplete. Only {0} of the expected {1} chunks were found, totaling {2} characters. A client size limit may have been exceeded.",
                                    chunkId - 1,
                                    chunksCount,
                                    totalSize));
                        }
                        // Missing chunk, abort by returning the original cookie value. It may have been a false positive?
                        return value;
                    }

                    chunks[chunkId - 1] = chunk;
                }

                return string.Join(string.Empty, chunks);
            }
            return value;
        }

        /// <summary>
        /// 将新的响应cookie附加到Set-Cookie标头。 如果Cookie大于给定的大小限制
         ///然后将其分解为多个cookie，如下所示：
        /// Set-Cookie: CookieName=chunks-3; path=/
        /// Set-Cookie: CookieNameC1=Segment1; path=/
        /// Set-Cookie: CookieNameC2=Segment2; path=/
        /// Set-Cookie: CookieNameC3=Segment3; path=/
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <param name="options"></param>
        public void AppendResponseCookie(HttpContext context, string key, string value, CookieOptions options)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var template = new SetCookieHeaderValue(key)
            {
                Domain = options.Domain,
                Expires = options.Expires,
                SameSite = (Net.Http.Headers.SameSiteMode)options.SameSite,
                HttpOnly = options.HttpOnly,
                Path = options.Path,
                Secure = options.Secure,
                MaxAge = options.MaxAge,
            };

            var templateLength = template.ToString().Length;

            value = value ?? string.Empty;

            // Normal cookie
            var responseCookies = context.Response.Cookies;
            if (!ChunkSize.HasValue || ChunkSize.Value > templateLength + value.Length)
            {
                responseCookies.Append(key, value, options);
            }
            else if (ChunkSize.Value < templateLength + 10)
            {
                // 10 is the minimum data we want to put in an individual cookie, including the cookie chunk identifier "CXX".
                // No room for data, we can't chunk the options and name
                throw new InvalidOperationException("The cookie key and options are larger than ChunksSize, leaving no room for data.");
            }
            else
            {
                // Break the cookie down into multiple cookies.
                // Key = CookieName, value = "Segment1Segment2Segment2"
                // Set-Cookie: CookieName=chunks-3; path=/
                // Set-Cookie: CookieNameC1="Segment1"; path=/
                // Set-Cookie: CookieNameC2="Segment2"; path=/
                // Set-Cookie: CookieNameC3="Segment3"; path=/
                var dataSizePerCookie = ChunkSize.Value - templateLength - 3; // Budget 3 chars for the chunkid.
                var cookieChunkCount = (int)Math.Ceiling(value.Length * 1.0 / dataSizePerCookie);

                responseCookies.Append(key, ChunkCountPrefix + cookieChunkCount.ToString(CultureInfo.InvariantCulture), options);

                var offset = 0;
                for (var chunkId = 1; chunkId <= cookieChunkCount; chunkId++)
                {
                    var remainingLength = value.Length - offset;
                    var length = Math.Min(dataSizePerCookie, remainingLength);
                    var segment = value.Substring(offset, length);
                    offset += length;

                    responseCookies.Append(key + ChunkKeySuffix + chunkId.ToString(CultureInfo.InvariantCulture), segment, options);
                }
            }
        }

        /// <summary>
        /// 通过设置过期状态来删除具有给定密钥的cookie。 如果存在匹配的分块Cookie
         ///请求，删除每个块。
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <param name="options"></param>
        public void DeleteCookie(HttpContext context, string key, CookieOptions options)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var keys = new List<string>();
            keys.Add(key + "=");

            var requestCookie = context.Request.Cookies[key];
            var chunks = ParseChunksCount(requestCookie);
            if (chunks > 0)
            {
                for (int i = 1; i <= chunks + 1; i++)
                {
                    var subkey = key + ChunkKeySuffix + i.ToString(CultureInfo.InvariantCulture);
                    keys.Add(subkey + "=");
                }
            }

            var domainHasValue = !string.IsNullOrEmpty(options.Domain);
            var pathHasValue = !string.IsNullOrEmpty(options.Path);

            Func<string, bool> rejectPredicate;
            Func<string, bool> predicate = value => keys.Any(k => value.StartsWith(k, StringComparison.OrdinalIgnoreCase));
            if (domainHasValue)
            {
                rejectPredicate = value => predicate(value) && value.IndexOf("domain=" + options.Domain, StringComparison.OrdinalIgnoreCase) != -1;
            }
            else if (pathHasValue)
            {
                rejectPredicate = value => predicate(value) && value.IndexOf("path=" + options.Path, StringComparison.OrdinalIgnoreCase) != -1;
            }
            else
            {
                rejectPredicate = value => predicate(value);
            }

            var responseHeaders = context.Response.Headers;
            var existingValues = responseHeaders[HeaderNames.SetCookie];
            if (!StringValues.IsNullOrEmpty(existingValues))
            {
                responseHeaders[HeaderNames.SetCookie] = existingValues.Where(value => !rejectPredicate(value)).ToArray();
            }

            AppendResponseCookie(
                context,
                key,
                string.Empty,
                new CookieOptions()
                {
                    Path = options.Path,
                    Domain = options.Domain,
                    SameSite = options.SameSite,
                    Secure = options.Secure,
                    IsEssential = options.IsEssential,
                    Expires = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                    HttpOnly = options.HttpOnly,
                });

            for (int i = 1; i <= chunks; i++)
            {
                AppendResponseCookie(
                    context,
                    key + "C" + i.ToString(CultureInfo.InvariantCulture),
                    string.Empty,
                    new CookieOptions()
                    {
                        Path = options.Path,
                        Domain = options.Domain,
                        SameSite = options.SameSite,
                        Secure = options.Secure,
                        IsEssential = options.IsEssential,
                        Expires = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                        HttpOnly = options.HttpOnly,
                    });
            }
        }
    }
```
### Constants
```
    internal static class Constants
    {
        internal static class Headers
        {
            internal const string SetCookie = "Set-Cookie";
        }
    }
```
### CookieAuthenticationDefaults
```
/// <summary>
    /// 与基于cookie的身份验证处理程序有关的默认值
    /// </summary>
    public static class CookieAuthenticationDefaults
    {
        /// <summary>
        /// CookieAuthenticationOptions.AuthenticationScheme使用的默认值
        /// </summary>
        public const string AuthenticationScheme = "Cookies";

        /// <summary>
        /// 用于提供默认CookieAuthenticationAuthentications.CookieName的前缀
        /// </summary>
        public static readonly string CookiePrefix = ".AspNetCore.";

        /// <summary>
        /// CookieAuthenticationMiddleware使用的默认值
         /// CookieAuthenticationOptions.LoginPath
        /// </summary>
        public static readonly PathString LoginPath = new PathString("/Account/Login");

        /// <summary>
        /// CookieAuthenticationMiddleware使用的默认值
         /// CookieAuthenticationOptions.LogoutPath
        /// </summary>
        public static readonly PathString LogoutPath = new PathString("/Account/Logout");

        /// <summary>
        /// CookieAuthenticationMiddleware使用的默认值
         /// CookieAuthenticationOptions.AccessDeniedPath
        /// </summary>
        public static readonly PathString AccessDeniedPath = new PathString("/Account/AccessDenied");

        /// <summary>
        /// CookieAuthenticationOptions.ReturnUrlParameter的默认值
        /// </summary>
        public static readonly string ReturnUrlParameter = "ReturnUrl";
    }
```
### CookieAuthenticationEvents
```
    /// <summary>
    /// 如果以下情况可以使用ICookieAuthenticationEvents的默认实现：
     ///应用程序仅需要重写一些接口方法。 这可以用作基类
     ///或可以直接实例化。
    /// </summary>
    public class CookieAuthenticationEvents
    {
        /// <summary>
        /// 调用相关方法时，将调用分配给此属性的委托。
        /// </summary>
        public Func<CookieValidatePrincipalContext, Task> OnValidatePrincipal { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// 调用相关方法时，将调用分配给此属性的委托。
        /// </summary>
        public Func<CookieSigningInContext, Task> OnSigningIn { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// 调用相关方法时，将调用分配给此属性的委托。
        /// </summary>
        public Func<CookieSignedInContext, Task> OnSignedIn { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// 调用相关方法时，将调用分配给此属性的委托。
        /// </summary>
        public Func<CookieSigningOutContext, Task> OnSigningOut { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// 调用相关方法时，将调用分配给此属性的委托。
        /// </summary>
        public Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToLogin { get; set; } = context =>
        {
            if (IsAjaxRequest(context.Request))
            {
                context.Response.Headers[HeaderNames.Location] = context.RedirectUri;
                context.Response.StatusCode = 401;
            }
            else
            {
                context.Response.Redirect(context.RedirectUri);
            }
            return Task.CompletedTask;
        };

        /// <summary>
        /// 调用相关方法时，将调用分配给此属性的委托。
        /// </summary>
        public Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToAccessDenied { get; set; } = context =>
        {
            if (IsAjaxRequest(context.Request))
            {
                context.Response.Headers[HeaderNames.Location] = context.RedirectUri;
                context.Response.StatusCode = 403;
            }
            else
            {
                context.Response.Redirect(context.RedirectUri);
            }
            return Task.CompletedTask;
        };

        /// <summary>
        /// 调用相关方法时，将调用分配给此属性的委托。
        /// </summary>
        public Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToLogout { get; set; } = context =>
        {
            if (IsAjaxRequest(context.Request))
            {
                context.Response.Headers[HeaderNames.Location] = context.RedirectUri;
            }
            else
            {
                context.Response.Redirect(context.RedirectUri);
            }
            return Task.CompletedTask;
        };

        /// <summary>
        /// 调用相关方法时，将调用分配给此属性的委托。
        /// </summary>
        public Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToReturnUrl { get; set; } = context =>
        {
            if (IsAjaxRequest(context.Request))
            {
                context.Response.Headers[HeaderNames.Location] = context.RedirectUri;
            }
            else
            {
                context.Response.Redirect(context.RedirectUri);
            }
            return Task.CompletedTask;
        };

        private static bool IsAjaxRequest(HttpRequest request)
        {
            return string.Equals(request.Query["X-Requested-With"], "XMLHttpRequest", StringComparison.Ordinal) ||
                string.Equals(request.Headers["X-Requested-With"], "XMLHttpRequest", StringComparison.Ordinal);
        }		

        /// <summary>
        /// 通过调用相关的委托方法来实现接口方法。
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public virtual Task ValidatePrincipal(CookieValidatePrincipalContext context) => OnValidatePrincipal(context);

        /// <summary>
        /// 通过调用相关的委托方法来实现接口方法。
        /// </summary>
        /// <param name="context"></param>
        public virtual Task SigningIn(CookieSigningInContext context) => OnSigningIn(context);

        /// <summary>
        /// 通过调用相关的委托方法来实现接口方法。
        /// </summary>
        /// <param name="context"></param>
        public virtual Task SignedIn(CookieSignedInContext context) => OnSignedIn(context);

        /// <summary>
        /// 通过调用相关的委托方法来实现接口方法。
        /// </summary>
        /// <param name="context"></param>
        public virtual Task SigningOut(CookieSigningOutContext context) => OnSigningOut(context);

        /// <summary>
        /// 通过调用相关的委托方法来实现接口方法。
        /// </summary>
        /// <param name="context">Contains information about the event</param>
        public virtual Task RedirectToLogout(RedirectContext<CookieAuthenticationOptions> context) => OnRedirectToLogout(context);

        /// <summary>
        /// 通过调用相关的委托方法来实现接口方法。
        /// </summary>
        /// <param name="context">Contains information about the event</param>
        public virtual Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context) => OnRedirectToLogin(context);

        /// <summary>
        /// 通过调用相关的委托方法来实现接口方法。
        /// </summary>
        /// <param name="context">Contains information about the event</param>
        public virtual Task RedirectToReturnUrl(RedirectContext<CookieAuthenticationOptions> context) => OnRedirectToReturnUrl(context);

        /// <summary>
        /// 通过调用相关的委托方法来实现接口方法。
        /// </summary>
        /// <param name="context">Contains information about the event</param>
        public virtual Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context) => OnRedirectToAccessDenied(context);
    }
```
### CookieAuthenticationHandler
```
    public class CookieAuthenticationHandler : SignInAuthenticationHandler<CookieAuthenticationOptions>
    {
        private const string HeaderValueNoCache = "no-cache";
        private const string HeaderValueEpocDate = "Thu, 01 Jan 1970 00:00:00 GMT";
        private const string SessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";

        private bool _shouldRefresh;
        private bool _signInCalled;
        private bool _signOutCalled;

        private DateTimeOffset? _refreshIssuedUtc;
        private DateTimeOffset? _refreshExpiresUtc;
        private string _sessionKey;
        private Task<AuthenticateResult> _readCookieTask;
        private AuthenticationTicket _refreshTicket;

        public CookieAuthenticationHandler(IOptionsMonitor<CookieAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        { }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new CookieAuthenticationEvents Events
        {
            get { return (CookieAuthenticationEvents)base.Events; }
            set { base.Events = value; }
        }

        protected override Task InitializeHandlerAsync()
        {
            // Cookies需要完成回复
            Context.Response.OnStarting(FinishResponseAsync);
            return Task.CompletedTask;
        }

        /// <summary>
        /// 创建事件实例的新实例。
        /// </summary>
        /// <returns>事件实例的新实例。</returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new CookieAuthenticationEvents());

        private Task<AuthenticateResult> EnsureCookieTicket()
        {
            // 我们只需要读一次票据
            if (_readCookieTask == null)
            {
                _readCookieTask = ReadCookieTicket();
            }
            return _readCookieTask;
        }

        private void CheckForRefresh(AuthenticationTicket ticket)
        {
            var currentUtc = Clock.UtcNow;
            var issuedUtc = ticket.Properties.IssuedUtc;
            var expiresUtc = ticket.Properties.ExpiresUtc;
            var allowRefresh = ticket.Properties.AllowRefresh ?? true;
            if (issuedUtc != null && expiresUtc != null && Options.SlidingExpiration && allowRefresh)
            {
                var timeElapsed = currentUtc.Subtract(issuedUtc.Value);
                var timeRemaining = expiresUtc.Value.Subtract(currentUtc);

                if (timeRemaining < timeElapsed)
                {
                    RequestRefresh(ticket);
                }
            }
        }

        private void RequestRefresh(AuthenticationTicket ticket, ClaimsPrincipal replacedPrincipal = null)
        {
            var issuedUtc = ticket.Properties.IssuedUtc;
            var expiresUtc = ticket.Properties.ExpiresUtc;

            if (issuedUtc != null && expiresUtc != null)
            {
                _shouldRefresh = true;
                var currentUtc = Clock.UtcNow;
                _refreshIssuedUtc = currentUtc;
                var timeSpan = expiresUtc.Value.Subtract(issuedUtc.Value);
                _refreshExpiresUtc = currentUtc.Add(timeSpan);
                _refreshTicket = CloneTicket(ticket, replacedPrincipal);
            }
        }

        private AuthenticationTicket CloneTicket(AuthenticationTicket ticket, ClaimsPrincipal replacedPrincipal)
        {
            var principal = replacedPrincipal ?? ticket.Principal;
            var newPrincipal = new ClaimsPrincipal();
            foreach (var identity in principal.Identities)
            {
                newPrincipal.AddIdentity(identity.Clone());
            }

            var newProperties = new AuthenticationProperties();
            foreach (var item in ticket.Properties.Items)
            {
                newProperties.Items[item.Key] = item.Value;
            }

            return new AuthenticationTicket(newPrincipal, newProperties, ticket.AuthenticationScheme);
        }

        private async Task<AuthenticateResult> ReadCookieTicket()
        {
            var cookie = Options.CookieManager.GetRequestCookie(Context, Options.Cookie.Name);
            if (string.IsNullOrEmpty(cookie))
            {
                return AuthenticateResult.NoResult();
            }

            var ticket = Options.TicketDataFormat.Unprotect(cookie, GetTlsTokenBinding());
            if (ticket == null)
            {
                return AuthenticateResult.Fail("Unprotect ticket failed");
            }

            if (Options.SessionStore != null)
            {
                var claim = ticket.Principal.Claims.FirstOrDefault(c => c.Type.Equals(SessionIdClaim));
                if (claim == null)
                {
                    return AuthenticateResult.Fail("SessionId missing");
                }
                _sessionKey = claim.Value;
                ticket = await Options.SessionStore.RetrieveAsync(_sessionKey);
                if (ticket == null)
                {
                    return AuthenticateResult.Fail("Identity missing in session store");
                }
            }

            var currentUtc = Clock.UtcNow;
            var expiresUtc = ticket.Properties.ExpiresUtc;

            if (expiresUtc != null && expiresUtc.Value < currentUtc)
            {
                if (Options.SessionStore != null)
                {
                    await Options.SessionStore.RemoveAsync(_sessionKey);
                }
                return AuthenticateResult.Fail("Ticket expired");
            }

            CheckForRefresh(ticket);

            // Finally we have a valid ticket
            return AuthenticateResult.Success(ticket);
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var result = await EnsureCookieTicket();
            if (!result.Succeeded)
            {
                return result;
            }

            var context = new CookieValidatePrincipalContext(Context, Scheme, Options, result.Ticket);
            await Events.ValidatePrincipal(context);

            if (context.Principal == null)
            {
                return AuthenticateResult.Fail("No principal.");
            }

            if (context.ShouldRenew)
            {
                RequestRefresh(result.Ticket, context.Principal);
            }

            return AuthenticateResult.Success(new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name));
        }

        private CookieOptions BuildCookieOptions()
        {
            var cookieOptions = Options.Cookie.Build(Context);
            // ignore the 'Expires' value as this will be computed elsewhere
            cookieOptions.Expires = null;

            return cookieOptions;
        }

        protected virtual async Task FinishResponseAsync()
        {
            // Only renew if requested, and neither sign in or sign out was called
            if (!_shouldRefresh || _signInCalled || _signOutCalled)
            {
                return;
            }

            var ticket = _refreshTicket;
            if (ticket != null)
            {
                var properties = ticket.Properties;

                if (_refreshIssuedUtc.HasValue)
                {
                    properties.IssuedUtc = _refreshIssuedUtc;
                }

                if (_refreshExpiresUtc.HasValue)
                {
                    properties.ExpiresUtc = _refreshExpiresUtc;
                }

                if (Options.SessionStore != null && _sessionKey != null)
                {
                    await Options.SessionStore.RenewAsync(_sessionKey, ticket);
                    var principal = new ClaimsPrincipal(
                        new ClaimsIdentity(
                            new[] { new Claim(SessionIdClaim, _sessionKey, ClaimValueTypes.String, Options.ClaimsIssuer) },
                            Scheme.Name));
                    ticket = new AuthenticationTicket(principal, null, Scheme.Name);
                }

                var cookieValue = Options.TicketDataFormat.Protect(ticket, GetTlsTokenBinding());

                var cookieOptions = BuildCookieOptions();
                if (properties.IsPersistent && _refreshExpiresUtc.HasValue)
                {
                    cookieOptions.Expires = _refreshExpiresUtc.Value.ToUniversalTime();
                }

                Options.CookieManager.AppendResponseCookie(
                    Context,
                    Options.Cookie.Name,
                    cookieValue,
                    cookieOptions);

                await ApplyHeaders(shouldRedirectToReturnUrl: false, properties: properties);
            }
        }

        protected async override Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            properties = properties ?? new AuthenticationProperties();

            _signInCalled = true;

            // Process the request cookie to initialize members like _sessionKey.
            await EnsureCookieTicket();
            var cookieOptions = BuildCookieOptions();

            var signInContext = new CookieSigningInContext(
                Context,
                Scheme,
                Options,
                user,
                properties,
                cookieOptions);

            DateTimeOffset issuedUtc;
            if (signInContext.Properties.IssuedUtc.HasValue)
            {
                issuedUtc = signInContext.Properties.IssuedUtc.Value;
            }
            else
            {
                issuedUtc = Clock.UtcNow;
                signInContext.Properties.IssuedUtc = issuedUtc;
            }

            if (!signInContext.Properties.ExpiresUtc.HasValue)
            {
                signInContext.Properties.ExpiresUtc = issuedUtc.Add(Options.ExpireTimeSpan);
            }

            await Events.SigningIn(signInContext);

            if (signInContext.Properties.IsPersistent)
            {
                var expiresUtc = signInContext.Properties.ExpiresUtc ?? issuedUtc.Add(Options.ExpireTimeSpan);
                signInContext.CookieOptions.Expires = expiresUtc.ToUniversalTime();
            }

            var ticket = new AuthenticationTicket(signInContext.Principal, signInContext.Properties, signInContext.Scheme.Name);

            if (Options.SessionStore != null)
            {
                if (_sessionKey != null)
                {
                    await Options.SessionStore.RemoveAsync(_sessionKey);
                }
                _sessionKey = await Options.SessionStore.StoreAsync(ticket);
                var principal = new ClaimsPrincipal(
                    new ClaimsIdentity(
                        new[] { new Claim(SessionIdClaim, _sessionKey, ClaimValueTypes.String, Options.ClaimsIssuer) },
                        Options.ClaimsIssuer));
                ticket = new AuthenticationTicket(principal, null, Scheme.Name);
            }

            var cookieValue = Options.TicketDataFormat.Protect(ticket, GetTlsTokenBinding());

            Options.CookieManager.AppendResponseCookie(
                Context,
                Options.Cookie.Name,
                cookieValue,
                signInContext.CookieOptions);

            var signedInContext = new CookieSignedInContext(
                Context,
                Scheme,
                signInContext.Principal,
                signInContext.Properties,
                Options);

            await Events.SignedIn(signedInContext);

            // Only redirect on the login path
            var shouldRedirect = Options.LoginPath.HasValue && OriginalPath == Options.LoginPath;
            await ApplyHeaders(shouldRedirect, signedInContext.Properties);

            Logger.AuthenticationSchemeSignedIn(Scheme.Name);
        }

        protected async override Task HandleSignOutAsync(AuthenticationProperties properties)
        {
            properties = properties ?? new AuthenticationProperties();

            _signOutCalled = true;

            // Process the request cookie to initialize members like _sessionKey.
            await EnsureCookieTicket();
            var cookieOptions = BuildCookieOptions();
            if (Options.SessionStore != null && _sessionKey != null)
            {
                await Options.SessionStore.RemoveAsync(_sessionKey);
            }

            var context = new CookieSigningOutContext(
                Context,
                Scheme,
                Options,
                properties,
                cookieOptions);

            await Events.SigningOut(context);

            Options.CookieManager.DeleteCookie(
                Context,
                Options.Cookie.Name,
                context.CookieOptions);

            // Only redirect on the logout path
            var shouldRedirect = Options.LogoutPath.HasValue && OriginalPath == Options.LogoutPath;
            await ApplyHeaders(shouldRedirect, context.Properties);

            Logger.AuthenticationSchemeSignedOut(Scheme.Name);
        }

        private async Task ApplyHeaders(bool shouldRedirectToReturnUrl, AuthenticationProperties properties)
        {
            Response.Headers[HeaderNames.CacheControl] = HeaderValueNoCache;
            Response.Headers[HeaderNames.Pragma] = HeaderValueNoCache;
            Response.Headers[HeaderNames.Expires] = HeaderValueEpocDate;

            if (shouldRedirectToReturnUrl && Response.StatusCode == 200)
            {
                 
                 //依次设置重定向uri：
                 // 1. properties.RedirectUri
                 // 2.查询参数ReturnUrlParameter
                 //
                 //如果它来自查询字符串，则不允许使用绝对uri，因为查询字符串不是
                 //受信任的来源。
                var redirectUri = properties.RedirectUri;
                if (string.IsNullOrEmpty(redirectUri))
                {
                    redirectUri = Request.Query[Options.ReturnUrlParameter];
                    if (string.IsNullOrEmpty(redirectUri) || !IsHostRelative(redirectUri))
                    {
                        redirectUri = null;
                    }
                }

                if (redirectUri != null)
                {
                    await Events.RedirectToReturnUrl(
                        new RedirectContext<CookieAuthenticationOptions>(Context, Scheme, Options, properties, redirectUri));
                }
            }
        }

        private static bool IsHostRelative(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }
            if (path.Length == 1)
            {
                return path[0] == '/';
            }
            return path[0] == '/' && path[1] != '/' && path[1] != '\\';
        }

        protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            var returnUrl = properties.RedirectUri;
            if (string.IsNullOrEmpty(returnUrl))
            {
                returnUrl = OriginalPathBase + OriginalPath + Request.QueryString;
            }
            var accessDeniedUri = Options.AccessDeniedPath + QueryString.Create(Options.ReturnUrlParameter, returnUrl);
            var redirectContext = new RedirectContext<CookieAuthenticationOptions>(Context, Scheme, Options, properties, BuildRedirectUri(accessDeniedUri));
            await Events.RedirectToAccessDenied(redirectContext);
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            var redirectUri = properties.RedirectUri;
            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
            }

            var loginUri = Options.LoginPath + QueryString.Create(Options.ReturnUrlParameter, redirectUri);
            var redirectContext = new RedirectContext<CookieAuthenticationOptions>(Context, Scheme, Options, properties, BuildRedirectUri(loginUri));
            await Events.RedirectToLogin(redirectContext);
        }

        private string GetTlsTokenBinding()
        {
            var binding = Context.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
            return binding == null ? null : Convert.ToBase64String(binding);
        }
    }
```
### CookieAuthenticationOptions
```
    /// <summary>
    /// <请参阅cref =“ CookieAuthenticationOptions” />的配置选项。
    /// </summary>
    public class CookieAuthenticationOptions : AuthenticationSchemeOptions
    {
        private CookieBuilder _cookieBuilder = new RequestPathBaseCookieBuilder
        {
            //默认名称在PostConfigureCookieAuthenticationOptions中配置

             //要支持OAuth身份验证，需要使用宽松模式，请参阅https://github.com/aspnet/Security/issues/1231。
            SameSite = SameSiteMode.Lax,
            HttpOnly = true,
            SecurePolicy = CookieSecurePolicy.SameAsRequest,
            IsEssential = true,
        };

        /// <summary>
        /// 创建使用默认值初始化的选项的实例
        /// </summary>
        public CookieAuthenticationOptions()
        {
            ExpireTimeSpan = TimeSpan.FromDays(14);
            ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
            SlidingExpiration = true;
            Events = new CookieAuthenticationEvents();
        }

        /// <summary>
        /// <para>
        /// 确定用于创建cookie的设置。
        /// </para>
        /// <para>
        /// <seealso cref="CookieBuilder.SameSite"/> 默认为<see cref =“ SameSiteMode.Lax” />。
        /// <seealso cref="CookieBuilder.HttpOnly"/> 默认为<c> true </ c>。
        /// <seealso cref="CookieBuilder.SecurePolicy"/> 默认为 <see cref="CookieSecurePolicy.SameAsRequest"/>.
        /// </para>
        /// </summary>
        /// <remarks>
        /// <para>
        /// Cookie名称的默认值为“ .AspNetCore.Cookies”。
         ///如果您更改AuthenticationScheme的名称，则应该更改此值，尤其是如果您更改了
         ///系统多次使用cookie身份验证处理程序。
        /// </para>
        /// <para>
        /// <seealso cref =“ CookieBuilder.SameSite” />确定浏览器是否应允许将cookie附加到同一站点或跨站点请求。
         ///默认值为Lax，这意味着仅允许使用安全的HTTP方法和同一站点请求将cookie附加到跨站点请求。
        /// </para>
        /// <para>
        /// <seealso cref =“ CookieBuilder.HttpOnly” />确定浏览器是否应允许客户端javascript访问cookie。
         ///默认值为true，这意味着cookie将仅传递给http请求，并且无法用于页面上的脚本。
        /// </para>
        /// <para>
        /// <seealso cref =“ CookieBuilder.Expiration” />当前被忽略。 使用<see cref =“ ExpireTimeSpan” />控制cookie身份验证的生存期。
        /// </para>
        /// </remarks>
        public CookieBuilder Cookie
        {
            get => _cookieBuilder;
            set => _cookieBuilder = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// 如果设置，则CookieAuthenticationHandler将使用它进行数据保护。
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }

        /// <summary>
        ///将SlidingExpiration设置为true，以指示处理程序使用新的cookie重新发出新的cookie。
         ///过期时间，只要它处理过期时间超过过期时间一半的请求。
        /// </summary>
        public bool SlidingExpiration { get; set; }

        /// <summary>
        /// 处理ChallengeAsync时，处理程序会将LoginPath属性用作重定向目标。
         ///当前的URL，作为由ReturnUrlParameter命名的查询字符串参数添加到LoginPath中。
         ///一旦对LoginPath的请求授予了新的SignIn身份，则使用ReturnUrlParameter值进行重定向
         ///浏览器回到原始网址。
        /// </summary>
        public PathString LoginPath { get; set; }

        /// <summary>
        /// 如果提供了LogoutPath处理程序，则将根据ReturnUrlParameter重定向到该路径的请求。
        /// </summary>
        public PathString LogoutPath { get; set; }

        /// <summary>
        ///处理ForbidAsync时，处理程序将AccessDeniedPath属性用作重定向目标。
        /// </summary>
        public PathString AccessDeniedPath { get; set; }

        /// <summary>
        /// ReturnUrlParameter确定查询字符串参数的名称，该名称由处理程序附加
         ///在hallengeAsync中。 这也是当请求到达时查询字符串参数
         ///登录路径或注销路径，以便在执行操作后返回到原始URL。
        /// </summary>
        public string ReturnUrlParameter { get; set; }

        /// <summary>
        /// 可以在启动时将提供者分配给应用程序创建的对象的实例。 处理程序
         ///调用提供程序上的方法，这些方法在发生处理的某些点上为应用程序提供控制。
         ///如果未提供，则提供默认实例，该默认实例在调用方法时不执行任何操作。
        /// </summary>
        public new CookieAuthenticationEvents Events
        {
            get => (CookieAuthenticationEvents)base.Events;
            set => base.Events = value;
        }

        /// <summary>
        /// TicketDataFormat用于保护和取消保护存储在服务器中的身份和其他属性。
         /// Cookie值。 如果未提供，将使用<see cref =“ DataProtectionProvider” />创建。
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> TicketDataFormat { get; set; }

        /// <summary>
        ///该组件用于从请求中获取Cookie或在响应中设置它们。
         ///
         ///默认情况下将使用ChunkingCookieManager。
        /// </summary>
        public ICookieManager CookieManager { get; set; }

        /// <summary>
        /// 一个可选容器，用于在各个请求中存储标识。 使用时，仅发送会话标识符
         ///到客户端。 这可以用来减轻具有很大标识的潜在问题。
        /// </summary>
        public ITicketStore SessionStore { get; set; }

        /// <summary>
        /// <para>
        /// 控制存储在cookie中的身份验证票证从创建之日起保持有效时间的时间
         ///到期信息存储在受保护的cookie票证中。 因此，过期的Cookie将被忽略
         ///即使在浏览器清除后将其传递给服务器也是如此。
        /// </para>
        /// <para>
        /// 这与<seealso cref =“ CookieOptions.Expires” />的值分开，后者指定
         ///浏览器将cookie保留多长时间。
        /// </para>
        /// </summary>
        public TimeSpan ExpireTimeSpan { get; set; }
    }
```
### CookieExtensions
```
    public static class CookieExtensions
    {
        public static AuthenticationBuilder AddCookie(this AuthenticationBuilder builder)
            => builder.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

        public static AuthenticationBuilder AddCookie(this AuthenticationBuilder builder, string authenticationScheme)
            => builder.AddCookie(authenticationScheme, configureOptions: null);

        public static AuthenticationBuilder AddCookie(this AuthenticationBuilder builder, Action<CookieAuthenticationOptions> configureOptions) 
            => builder.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddCookie(this AuthenticationBuilder builder, string authenticationScheme, Action<CookieAuthenticationOptions> configureOptions)
            => builder.AddCookie(authenticationScheme, displayName: null, configureOptions: configureOptions);

        public static AuthenticationBuilder AddCookie(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<CookieAuthenticationOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CookieAuthenticationOptions>, PostConfigureCookieAuthenticationOptions>());
            builder.Services.AddOptions<CookieAuthenticationOptions>(authenticationScheme).Validate(o => o.Cookie.Expiration == null, "Cookie.Expiration is ignored, use ExpireTimeSpan instead.");
            return builder.AddScheme<CookieAuthenticationOptions, CookieAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
```
### CookieSignedInContext
```
    /// <summary>
    /// 上下文对象传递给ICookieAuthenticationEvents方法SignedIn。
    /// </summary>    
    public class CookieSignedInContext : PrincipalContext<CookieAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new instance of the context object.
        /// </summary>
        /// <param name="context">The HTTP request context</param>
        /// <param name="scheme">The scheme data</param>
        /// <param name="principal">Initializes Principal property</param>
        /// <param name="properties">Initializes Properties property</param>
        /// <param name="options">The handler options</param>
        public CookieSignedInContext(
            HttpContext context,
            AuthenticationScheme scheme,
            ClaimsPrincipal principal,
            AuthenticationProperties properties,
            CookieAuthenticationOptions options)
            : base(context, scheme, options, properties)
        {
            Principal = principal;
        }
    }
```
### CookieSigningInContext
```
    /// <summary>
    ///上下文对象传递给<see cref =“ CookieAuthenticationEvents.SigningIn（CookieSigningInContext）” />。
    /// </summary>    
    public class CookieSigningInContext : PrincipalContext<CookieAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new instance of the context object.
        /// </summary>
        /// <param name="context">The HTTP request context</param>
        /// <param name="scheme">The scheme data</param>
        /// <param name="options">The handler options</param>
        /// <param name="principal">Initializes Principal property</param>
        /// <param name="properties">The authentication properties.</param>
        /// <param name="cookieOptions">Initializes options for the authentication cookie.</param>
        public CookieSigningInContext(
            HttpContext context,
            AuthenticationScheme scheme,
            CookieAuthenticationOptions options,
            ClaimsPrincipal principal,
            AuthenticationProperties properties,
            CookieOptions cookieOptions)
            : base(context, scheme, options, properties)
        {
            CookieOptions = cookieOptions;
            Principal = principal;
        }

        /// <summary>
        /// The options for creating the outgoing cookie.
        /// May be replace or altered during the SigningIn call.
        /// </summary>
        public CookieOptions CookieOptions { get; set; }
    }
```
### CookieSigningOutContext
```
/// <summary>
    /// Context object passed to the <see cref="CookieAuthenticationEvents.SigningOut(CookieSigningOutContext)"/>
    /// </summary>
    public class CookieSigningOutContext : PropertiesContext<CookieAuthenticationOptions>
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="properties"></param>
        /// <param name="cookieOptions"></param>
        public CookieSigningOutContext(
            HttpContext context,
            AuthenticationScheme scheme,
            CookieAuthenticationOptions options, 
            AuthenticationProperties properties, 
            CookieOptions cookieOptions)
            : base(context, scheme, options, properties)
            => CookieOptions = cookieOptions;

        /// <summary>
        /// The options for creating the outgoing cookie.
        /// May be replace or altered during the SigningOut call.
        /// </summary>
        public CookieOptions CookieOptions { get; set; }
    }
```
### CookieValidatePrincipalContext
```
    /// <summary>
    /// 上下文对象传递给CookieAuthenticationEvents ValidatePrincipal方法。
    /// </summary>
    public class CookieValidatePrincipalContext : PrincipalContext<CookieAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new instance of the context object.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="ticket">Contains the initial values for identity and extra data</param>
        /// <param name="options"></param>
        public CookieValidatePrincipalContext(HttpContext context, AuthenticationScheme scheme, CookieAuthenticationOptions options, AuthenticationTicket ticket)
            : base(context, scheme, options, ticket?.Properties)
        {
            if (ticket == null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            Principal = ticket.Principal;
        }

        /// <summary>
        /// 如果为true，则将更新Cookie
        /// </summary>
        public bool ShouldRenew { get; set; }

        /// <summary>
        /// Called to replace the claims principal. The supplied principal will replace the value of the 
        /// Principal property, which determines the identity of the authenticated request.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> used as the replacement</param>
        public void ReplacePrincipal(ClaimsPrincipal principal) => Principal = principal;

        /// <summary>
        /// Called to reject the incoming principal. This may be done if the application has determined the
        /// account is no longer active, and the request should be treated as if it was anonymous.
        /// </summary>
        public void RejectPrincipal() => Principal = null;
    }
```

### ICookieManager
```
    /// <summary>
    ///CookieAuthenticationMiddleware使用它来处理请求和响应cookie。
     ///它是从常规Cookie API中抽象出来的，以允许诸如分块之类的复杂操作。
    /// </summary>
    public interface ICookieManager
    {
        /// <summary>
        /// 从请求中检索具有给定名称的cookie。
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        string GetRequestCookie(HttpContext context, string key);

        /// <summary>
        /// 将给定的Cookie附加到响应中。
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <param name="options"></param>
        void AppendResponseCookie(HttpContext context, string key, string value, CookieOptions options);

        /// <summary>
        /// 将删除Cookie附加到响应中。
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <param name="options"></param>
        void DeleteCookie(HttpContext context, string key, CookieOptions options);
    }
```

### ITicketStore
```
    /// <summary>
///这提供了一种抽象的存储机制来将身份信息保留在服务器上
     ///同时仅向客户端发送简单的标识符密钥。 这是最常用的缓解
     ///将大型身份序列化为cookie的问题。
    /// </summary>
    public interface ITicketStore
    {
        /// <summary>
        /// 存储身份票证并返回关联的密钥。
        /// </summary>
        /// <param name="ticket">The identity information to store.</param>
        /// <returns>The key that can be used to retrieve the identity later.</returns>
        Task<string> StoreAsync(AuthenticationTicket ticket);

        /// <summary>
        /// 告诉存储应该更新给定的身份。
        /// </summary>
        /// <param name="key"></param>
        /// <param name="ticket"></param>
        /// <returns></returns>
        Task RenewAsync(string key, AuthenticationTicket ticket);

        /// <summary>
        ///从存储中检索给定密钥的标识。
        /// </summary>
        /// <param name="key">与身份相关的密钥.</param>
        /// <returns>与给定密钥关联的身份，如果找不到。</returns>
        Task<AuthenticationTicket> RetrieveAsync(string key);

        /// <summary>
        /// 删除与给定密钥关联的身份。
        /// </summary>
        /// <param name="key">与身份相关的密钥.</param>
        /// <returns></returns>
        Task RemoveAsync(string key);
    }
```
### PostConfigureCookieAuthenticationOptions
```
    /// <summary>
    /// 用于为所有<see cref =“ CookieAuthenticationOptions” />设置默认值。
    /// </summary>
    public class PostConfigureCookieAuthenticationOptions : IPostConfigureOptions<CookieAuthenticationOptions>
    {
        private readonly IDataProtectionProvider _dp;

        public PostConfigureCookieAuthenticationOptions(IDataProtectionProvider dataProtection)
        {
            _dp = dataProtection;
        }

        /// <summary>
        /// 调用以发布配置TOptions实例。
        /// </summary>
        /// <param name="name">正在配置的选项实例的名称。</param>
        /// <param name="options">要配置的选项实例。</param>
        public void PostConfigure(string name, CookieAuthenticationOptions options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;

            if (string.IsNullOrEmpty(options.Cookie.Name))
            {
                options.Cookie.Name = CookieAuthenticationDefaults.CookiePrefix + name;
            }
            if (options.TicketDataFormat == null)
            {
                // Note: the purpose for the data protector must remain fixed for interop to work.
                var dataProtector = options.DataProtectionProvider.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", name, "v2");
                options.TicketDataFormat = new TicketDataFormat(dataProtector);
            }
            if (options.CookieManager == null)
            {
                options.CookieManager = new ChunkingCookieManager();
            }
            if (!options.LoginPath.HasValue)
            {
                options.LoginPath = CookieAuthenticationDefaults.LoginPath;
            }
            if (!options.LogoutPath.HasValue)
            {
                options.LogoutPath = CookieAuthenticationDefaults.LogoutPath;
            }
            if (!options.AccessDeniedPath.HasValue)
            {
                options.AccessDeniedPath = CookieAuthenticationDefaults.AccessDeniedPath;
            }
        }
    }
```