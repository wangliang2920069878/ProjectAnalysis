|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AppendCookieContext](#appendcookiecontext)
* [CookiePolicyAppBuilderExtensions](#cookiepolicyappbuilderextensions)
* [CookiePolicyMiddleware](#cookiepolicymiddleware)
* [CookiePolicyOptions](#cookiepolicyoptions)
* [DeleteCookieContext](#deletecookiecontext)
* [HttpOnlyPolicy](#httponlypolicy)
* [ResponseCookiesWrapper](#responsecookieswrapper)


### AppendCookieContext
```
    public class AppendCookieContext
    {
        public AppendCookieContext(HttpContext context, CookieOptions options, string name, string value)
        {
            Context = context;
            CookieOptions = options;
            CookieName = name;
            CookieValue = value;
        }

        public HttpContext Context { get; }
        public CookieOptions CookieOptions { get; }
        public string CookieName { get; set; }
        public string CookieValue { get; set; }
        public bool IsConsentNeeded { get; internal set; }
        public bool HasConsent { get; internal set; }
        public bool IssueCookie { get; set; }
    }
```
### CookiePolicyAppBuilderExtensions
```
    /// <summary>
    /// 用于将cookie策略功能添加到HTTP应用程序管道的扩展方法。
    /// </summary>
    public static class CookiePolicyAppBuilderExtensions
    {
        /// <summary>
        /// Adds the <see cref="CookiePolicyMiddleware"/> handler to the specified <see cref="IApplicationBuilder"/>, which enables cookie policy capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the handler to.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseCookiePolicy(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<CookiePolicyMiddleware>();
        }

        /// <summary>
        ///将<see cref =“ CookiePolicyMiddleware” />处理程序添加到指定的<see cref =“ IApplicationBuilder” />，这将启用cookie策略功能。
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the handler to.</param>
        /// <param name="options">A <see cref="CookiePolicyOptions"/> that specifies options for the handler.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseCookiePolicy(this IApplicationBuilder app, CookiePolicyOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<CookiePolicyMiddleware>(Options.Create(options));
        }
    }
```
### CookiePolicyMiddleware
```
    public class CookiePolicyMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger _logger;

        public CookiePolicyMiddleware(RequestDelegate next, IOptions<CookiePolicyOptions> options, ILoggerFactory factory)
        {
            Options = options.Value;
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _logger = factory.CreateLogger<CookiePolicyMiddleware>();
        }

        public CookiePolicyMiddleware(RequestDelegate next, IOptions<CookiePolicyOptions> options)
        {
            Options = options.Value;
            _next = next;
            _logger = NullLogger.Instance;
        }

        public CookiePolicyOptions Options { get; set; }

        public Task Invoke(HttpContext context)
        {
            var feature = context.Features.Get<IResponseCookiesFeature>() ?? new ResponseCookiesFeature(context.Features);
            var wrapper = new ResponseCookiesWrapper(context, Options, feature, _logger);
            context.Features.Set<IResponseCookiesFeature>(new CookiesWrapperFeature(wrapper));
            context.Features.Set<ITrackingConsentFeature>(wrapper);

            return _next(context);
        }

        private class CookiesWrapperFeature : IResponseCookiesFeature
        {
            public CookiesWrapperFeature(ResponseCookiesWrapper wrapper)
            {
                Cookies = wrapper;
            }

            public IResponseCookies Cookies { get; }
        }
    }
```
### CookiePolicyOptions
```
    /// <summary>
    /// 为<see cref =“ CookiePolicyMiddleware” />提供编程配置。
    /// </summary>
    public class CookiePolicyOptions
    {
        /// <summary>
        /// 影响cookie的相同站点属性。
        /// </summary>
        public SameSiteMode MinimumSameSitePolicy { get; set; } = SameSiteMode.None;

        /// <summary>
        /// 影响cookie是否必须为HttpOnly。
        /// </summary>
        public HttpOnlyPolicy HttpOnly { get; set; } = HttpOnlyPolicy.None;

        /// <summary>
        /// 影响cookie是否必须安全。
        /// </summary>
        public CookieSecurePolicy Secure { get; set; } = CookieSecurePolicy.None;

        public CookieBuilder ConsentCookie { get; set; } = new CookieBuilder()
        {
            Name = ".AspNet.Consent",
            Expiration = TimeSpan.FromDays(365),
            IsEssential = true,
        };

        /// <summary>
        ///检查是否应对此请求评估同意策略。 默认为false。
        /// </summary>
        public Func<HttpContext, bool> CheckConsentNeeded { get; set; }

        /// <summary>
        /// 附加Cookie时调用。
        /// </summary>
        public Action<AppendCookieContext> OnAppendCookie { get; set; }

        /// <summary>
        ///删除Cookie时调用。
        /// </summary>
        public Action<DeleteCookieContext> OnDeleteCookie { get; set; }
    }
```
### DeleteCookieContext
```
    public class DeleteCookieContext
    {
        public DeleteCookieContext(HttpContext context, CookieOptions options, string name)
        {
            Context = context;
            CookieOptions = options;
            CookieName = name;
        }

        public HttpContext Context { get; }
        public CookieOptions CookieOptions { get; }
        public string CookieName { get; set; }
        public bool IsConsentNeeded { get; internal set; }
        public bool HasConsent { get; internal set; }
        public bool IssueCookie { get; set; }
    }
```
### HttpOnlyPolicy
```
    public enum HttpOnlyPolicy
    {
        None,
        Always
    }
```
### ResponseCookiesWrapper
```
    internal class ResponseCookiesWrapper : IResponseCookies, ITrackingConsentFeature
    {
        private const string ConsentValue = "yes";
        private readonly ILogger _logger;
        private bool? _isConsentNeeded;
        private bool? _hasConsent;

        public ResponseCookiesWrapper(HttpContext context, CookiePolicyOptions options, IResponseCookiesFeature feature, ILogger logger)
        {
            Context = context;
            Feature = feature;
            Options = options;
            _logger = logger;
        }

        private HttpContext Context { get; }

        private IResponseCookiesFeature Feature { get; }

        private IResponseCookies Cookies => Feature.Cookies;

        private CookiePolicyOptions Options { get; }

        public bool IsConsentNeeded
        {
            get
            {
                if (!_isConsentNeeded.HasValue)
                {
                    _isConsentNeeded = Options.CheckConsentNeeded == null ? false
                        : Options.CheckConsentNeeded(Context);
                    _logger.NeedsConsent(_isConsentNeeded.Value);
                }

                return _isConsentNeeded.Value;
            }
        }

        public bool HasConsent
        {
            get
            {
                if (!_hasConsent.HasValue)
                {
                    var cookie = Context.Request.Cookies[Options.ConsentCookie.Name];
                    _hasConsent = string.Equals(cookie, ConsentValue, StringComparison.Ordinal);
                    _logger.HasConsent(_hasConsent.Value);
                }

                return _hasConsent.Value;
            }
        }

        public bool CanTrack => !IsConsentNeeded || HasConsent;

        public void GrantConsent()
        {
            if (!HasConsent && !Context.Response.HasStarted)
            {
                var cookieOptions = Options.ConsentCookie.Build(Context);
                // 注意政策将适用。 我们不想绕过策略，因为我们希望应用HttpOnly，Secure等。
                Append(Options.ConsentCookie.Name, ConsentValue, cookieOptions);
                _logger.ConsentGranted();
            }
            _hasConsent = true;
        }

        public void WithdrawConsent()
        {
            if (HasConsent && !Context.Response.HasStarted)
            {
                var cookieOptions = Options.ConsentCookie.Build(Context);
                // 注意政策将适用。 我们不想绕过策略，因为我们希望应用HttpOnly，Secure等。
                Delete(Options.ConsentCookie.Name, cookieOptions);
                _logger.ConsentWithdrawn();
            }
            _hasConsent = false;
        }

        // 注意政策将适用。 我们不想绕过策略，因为我们希望应用HttpOnly，Secure等。
        public string CreateConsentCookie()
        {
            var key = Options.ConsentCookie.Name;
            var value = ConsentValue;
            var options = Options.ConsentCookie.Build(Context);
            ApplyAppendPolicy(ref key, ref value, options);

            var setCookieHeaderValue = new Net.Http.Headers.SetCookieHeaderValue(
                Uri.EscapeDataString(key),
                Uri.EscapeDataString(value))
                {
                    Domain = options.Domain,
                    Path = options.Path,
                    Expires = options.Expires,
                    MaxAge = options.MaxAge,
                    Secure = options.Secure,
                    SameSite = (Net.Http.Headers.SameSiteMode)options.SameSite,
                    HttpOnly = options.HttpOnly
                };

            return setCookieHeaderValue.ToString();
        }

        private bool CheckPolicyRequired()
        {
            return !CanTrack
                || Options.MinimumSameSitePolicy != SameSiteMode.None
                || Options.HttpOnly != HttpOnlyPolicy.None
                || Options.Secure != CookieSecurePolicy.None;
        }

        public void Append(string key, string value)
        {
            if (CheckPolicyRequired() || Options.OnAppendCookie != null)
            {
                Append(key, value, new CookieOptions());
            }
            else
            {
                Cookies.Append(key, value);
            }
        }

        public void Append(string key, string value, CookieOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (ApplyAppendPolicy(ref key, ref value, options))
            {
                Cookies.Append(key, value, options);
            }
            else
            {
                _logger.CookieSuppressed(key);
            }
        }

        private bool ApplyAppendPolicy(ref string key, ref string value, CookieOptions options)
        {
            var issueCookie = CanTrack || options.IsEssential;
            ApplyPolicy(key, options);
            if (Options.OnAppendCookie != null)
            {
                var context = new AppendCookieContext(Context, options, key, value)
                {
                    IsConsentNeeded = IsConsentNeeded,
                    HasConsent = HasConsent,
                    IssueCookie = issueCookie,
                };
                Options.OnAppendCookie(context);

                key = context.CookieName;
                value = context.CookieValue;
                issueCookie = context.IssueCookie;
            }

            return issueCookie;
        }

        public void Delete(string key)
        {
            if (CheckPolicyRequired() || Options.OnDeleteCookie != null)
            {
                Delete(key, new CookieOptions());
            }
            else
            {
                Cookies.Delete(key);
            }
        }

        public void Delete(string key, CookieOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Assume you can always delete cookies unless directly overridden in the user event.
            var issueCookie = true;
            ApplyPolicy(key, options);
            if (Options.OnDeleteCookie != null)
            {
                var context = new DeleteCookieContext(Context, options, key)
                {
                    IsConsentNeeded = IsConsentNeeded,
                    HasConsent = HasConsent,
                    IssueCookie = issueCookie,
                };
                Options.OnDeleteCookie(context);

                key = context.CookieName;
                issueCookie = context.IssueCookie;
            }

            if (issueCookie)
            {
                Cookies.Delete(key, options);
            }
            else
            {
                _logger.DeleteCookieSuppressed(key);
            }
        }

        private void ApplyPolicy(string key, CookieOptions options)
        {
            switch (Options.Secure)
            {
                case CookieSecurePolicy.Always:
                    if (!options.Secure)
                    {
                        options.Secure = true;
                        _logger.CookieUpgradedToSecure(key);
                    }
                    break;
                case CookieSecurePolicy.SameAsRequest:
                    // Never downgrade a cookie
                    if (Context.Request.IsHttps && !options.Secure)
                    {
                        options.Secure = true;
                        _logger.CookieUpgradedToSecure(key);
                    }
                    break;
                case CookieSecurePolicy.None:
                    break;
                default:
                    throw new InvalidOperationException();
            }
            switch (Options.MinimumSameSitePolicy)
            {
                case SameSiteMode.None:
                    break;
                case SameSiteMode.Lax:
                    if (options.SameSite == SameSiteMode.None)
                    {
                        options.SameSite = SameSiteMode.Lax;
                        _logger.CookieSameSiteUpgraded(key, "lax");
                    }
                    break;
                case SameSiteMode.Strict:
                    if (options.SameSite != SameSiteMode.Strict)
                    {
                        options.SameSite = SameSiteMode.Strict;
                        _logger.CookieSameSiteUpgraded(key, "strict");
                    }
                    break;
                default:
                    throw new InvalidOperationException($"Unrecognized {nameof(SameSiteMode)} value {Options.MinimumSameSitePolicy.ToString()}");
            }
            switch (Options.HttpOnly)
            {
                case HttpOnlyPolicy.Always:
                    if (!options.HttpOnly)
                    {
                        options.HttpOnly = true;
                        _logger.CookieUpgradedToHttpOnly(key);
                    }
                    break;
                case HttpOnlyPolicy.None:
                    break;
                default:
                    throw new InvalidOperationException($"Unrecognized {nameof(HttpOnlyPolicy)} value {Options.HttpOnly.ToString()}");
            }
        }
    }
```