|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [IAuthenticationFeature](#iauthenticationfeature)
* [IAuthenticationHandler](#iauthenticationhandler)
* [IAuthenticationHandlerProvider](#iauthenticationhandlerprovider)
* [IAuthenticationRequestHandler](#iauthenticationrequesthandler)
* [IAuthenticationSchemeProvider](#iauthenticationschemeprovider)
* [IAuthenticationService](#iauthenticationservice)
* [IAuthenticationSignInHandler](#iauthenticationsigninhandler)
* [IAuthenticationSignOutHandler](#iauthenticationsignouthandler)
* [IClaimsTransformation](#iclaimstransformation)
* [AuthenticateResult](#authenticateresult)
* [AuthenticationProperties](#authenticationproperties)
* [AuthenticationTicket](#authenticationticket)
* [AuthenticationHttpContextExtensions](#authenticationhttpcontextextensions)
* [AuthenticationOptions](#authenticationoptions)
* [AuthenticationScheme](#authenticationscheme)
* [AuthenticationSchemeBuilder](#authenticationschemeBuilder)
* [AuthenticationToken](#authenticationtoken)
* [AuthenticationTokenExtensions](#authenticationtokenextensions)
### IAuthenticationFeature
    //用于捕获路径信息，因此可以在app.Map（）中正确计算重定向。
```
        /// <summary>
        /// 原始基路径
        /// </summary>
        PathString OriginalPathBase { get; set; }

        /// <summary>
        /// 原始路径。
        /// </summary>
        PathString OriginalPath { get; set; }
```
### IAuthenticationHandler
    //根据请求创建，以处理针对特定方案的身份验证。
```
        /// <summary>
        /// 处理程序应在此处初始化请求和方案所需的任何内容。
        /// </summary>
        Task InitializeAsync(AuthenticationScheme scheme, HttpContext context);

        /// <summary>
        /// 身份验证行为。
        /// </summary>
        Task<AuthenticateResult> AuthenticateAsync();

        /// <summary>
        /// 握手认证行为
        返回一个需要认证的标识来提示用户登录，通常会返回一个 401 状态码。
        /// </summary>
        Task ChallengeAsync(AuthenticationProperties properties);

        /// <summary>
        /// 禁上访问，表示用户权限不足，通常会返回一个 403 状态码。
        /// </summary>
        Task ForbidAsync(AuthenticationProperties properties);
```
### IAuthenticationHandlerProvider
    //为authenticationScheme和请求提供适当的IAuthenticationHandler实例。
```
        /// <summary>
        /// 返回将使用的处理程序实例。
        /// </summary>

        Task<IAuthenticationHandler> GetHandlerAsync(HttpContext context, string authenticationScheme);
```
### IAuthenticationRequestHandler
    //用于确定处理程序是否要参与请求处理。
```
        /// <summary>
        ///如果请求处理应该停止，则返回true。
        /// </summary>

        Task<bool> HandleRequestAsync();
```
### IAuthenticationSchemeProvider
    //负责管理支持哪些身份验证方案。
```
        /// <summary>
        /// 返回所有当前已注册的<see cref =“ AuthenticationScheme” />。
        /// </summary>

        Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync();

        /// <summary>
        /// 返回与名称匹配的<see cref =“ AuthenticationScheme” />或null。
        /// </summary>

        Task<AuthenticationScheme> GetSchemeAsync(string name);

        /// <summary>
        /// 返回默认情况下将用于<see cref =“ IAuthenticationService.AuthenticateAsync（HttpContext，string）” />的方案。通常通过<see cref =“ AuthenticationOptions.DefaultAuthenticateScheme” />指定。否则，它将回退到<see cref =“AuthenticationOptions.DefaultSchem>。
        /// </summary>

        Task<AuthenticationScheme> GetDefaultAuthenticateSchemeAsync();

        /// <summary>
            返回默认情况下将用于<see cref =“ IAuthenticationService.ChallengeAsync（HttpContext，string，AuthenticationProperties）” />的方案。
            通常通过<see cref =“ AuthenticationOptions.DefaultChallengeScheme” /            >指定。
            否则，它将回退到<see cref =“ AuthenticationOptions.DefaultScheme” />。
        /// </summary>
        Task<AuthenticationScheme> GetDefaultChallengeSchemeAsync();

        /// <summary>
           返回默认用于<see cref =“ IAuthenticationService.ForbidAsync（HttpContext，string，AuthenticationProperties）” />的方案。
            通常是通过<see cref =“ AuthenticationOptions.DefaultForbidScheme” />      指定的。
         否则，它将回退到<see cref =“ GetDefaultChallengeSchemeAsync” />。
        /// </summary>
        Task<AuthenticationScheme> GetDefaultForbidSchemeAsync();

        /// <summary>
        ///返回默认用于<see cref =“ IAuthenticationService.SignInAsync（HttpContext，string，System.Security.Claims.ClaimsPrincipal，AuthenticationProperties）” />的方案。
         ///通常是通过<see cref =“ AuthenticationOptions.DefaultSignInScheme” />指定。
         ///否则，它将回退到<see cref =“ AuthenticationOptions.DefaultScheme” />。
        /// </summary>
        Task<AuthenticationScheme> GetDefaultSignInSchemeAsync();

        /// <summary>
       ///返回默认用于<see cref =“ IAuthenticationService.SignOutAsync（HttpContext，string，AuthenticationProperties）” />的方案。
         ///通常通过<see cref =“ AuthenticationOptions.DefaultSignOutScheme” />指定。
         ///否则，它将回退到<see cref =“ GetDefaultSignInSchemeAsync” />。
        /// </summary>
        Task<AuthenticationScheme> GetDefaultSignOutSchemeAsync();

        /// <summary>
        /// 注册供<see cref =“ IAuthenticationService” />使用的方案。
        /// </summary>
        void AddScheme(AuthenticationScheme scheme);

        /// <summary>
        /// 删除一个方案，以防止它被<see cref =“ IAuthenticationService” />使用。
        /// </summary>
        void RemoveScheme(string name);

        /// <summary>
        /// 以优先级顺序返回方案以进行请求处理。
        /// </summary>
        Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync();
```
### IAuthenticationService
    //用于提供身份验证。
```
        /// <summary>
        /// 针对指定的身份验证方案进行身份验证。
        /// </summary>
        Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string scheme);

        /// <summary>
        /// 握手指定的身份验证方案。
        /// </summary>
        Task ChallengeAsync(HttpContext context, string scheme, AuthenticationProperties properties);

        /// <summary>
        /// 禁止指定的认证方案。
        /// </summary>
        Task ForbidAsync(HttpContext context, string scheme, AuthenticationProperties properties);

        /// <summary>
        /// 登录指定身份验证方案的主体。
        /// </summary>
        Task SignInAsync(HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties);

        /// <summary>
        /// 注销指定的身份验证方案。
        /// </summary>
        Task SignOutAsync(HttpContext context, string scheme, AuthenticationProperties properties);
```
### IAuthenticationSignInHandler
    //用于确定处理程序是否支持SignIn。
```
处理登录。
Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties properties);
```
### IAuthenticationSignOutHandler
    //用于确定处理程序是否支持SignOut。
```
登出行为。
 Task SignOutAsync(AuthenticationProperties properties);
```
### IClaimsTransformation
    //由<see cref =“ IAuthenticationService” /> />用于声明转换。
```
提供一个中心转换点以更改指定的主体。
注意：这将在每个AuthenticateAsync调用上运行，因此更安全
如果您的变换不是幂等的，则返回一个新的ClaimsPrincipal。
Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal);
```
### AuthenticateResult
    //包含身份验证方法调用的结果

属性
```
public bool Succeeded => Ticket != null;

//如果生成了票证，则验证成功。
```
```
public ClaimsPrincipal Principal => Ticket?.Principal;

获取具有已验证用户身份的声明主体。
```
```
public AuthenticationProperties Properties { get; protected set; }

身份验证会话的其它状态值。
```
```
public Exception Failure { get; protected set; }

保留来自身份验证的失败信息。
```
```
public bool None { get; protected set; }

表示没有为此认证方案返回任何信息。
```
方法
```
        public static AuthenticateResult Success(AuthenticationTicket ticket)
        {
            if (ticket == null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }
            return new AuthenticateResult() { Ticket = ticket, Properties = ticket.Properties };
        }

        表示认证成功。
```
```
        public static AuthenticateResult NoResult()
        {
            return new AuthenticateResult() { None = true };
        }

        表示没有为此认证方案返回任何信息。
```

```
        public static AuthenticateResult Fail(Exception failure)
        {
            return new AuthenticateResult() { Failure = failure };
        }

        指示认证期间失败。
```
```
        public static AuthenticateResult Fail(Exception failure, AuthenticationProperties properties)
        {
            return new AuthenticateResult() { Failure = failure, Properties = properties };
        }

        指示认证期间失败。
```
```
        public static AuthenticateResult Fail(string failureMessage)
            => Fail(new Exception(failureMessage));

         指示认证期间失败。
```
```
        public static AuthenticateResult Fail(string failureMessage, AuthenticationProperties properties)
            => Fail(new Exception(failureMessage), properties);

        指示认证期间失败。
```

### AuthenticationProperties
    //字典，用于存储有关身份验证会话的状态值。
const 属性
```
        internal const string IssuedUtcKey = ".issued";
        internal const string ExpiresUtcKey = ".expires";
        internal const string IsPersistentKey = ".persistent";
        internal const string RedirectUriKey = ".redirect";
        internal const string RefreshKey = ".refresh";
        internal const string UtcDateTimeFormat = "r";

        //应该是用作字典的key
```
属性
```
public IDictionary<string, string> Items { get; }

//关于认证会话的状态值。
```
```
public IDictionary<string, object> Parameters { get; }

//传递给身份验证处理程序的参数的集合。 这些不适用于
  序列化或持久性，仅用于在呼叫站点之间流动数据。
```
```
        public bool IsPersistent
        {
            get => GetString(IsPersistentKey) != null;
            set => SetString(IsPersistentKey, value ? string.Empty : null);
        }

        //获取或设置是否在多个请求之间保留身份验证会话。
```
```
        public string RedirectUri
        {
            get => GetString(RedirectUriKey);
            set => SetString(RedirectUriKey, value);
        }
        //获取或设置要用作http重定向响应值的完整路径或绝对URI。
```
```
        public DateTimeOffset? IssuedUtc
        {
            get => GetDateTimeOffset(IssuedUtcKey);
            set => SetDateTimeOffset(IssuedUtcKey, value);
        }

        获取或设置颁发身份验证票证的时间。
```
```
        public DateTimeOffset? ExpiresUtc
        {
            get => GetDateTimeOffset(ExpiresUtcKey);
            set => SetDateTimeOffset(ExpiresUtcKey, value);
        }

        获取或设置身份验证票证过期的时间。
```
```
        public bool? AllowRefresh
        {
            get => GetBool(RefreshKey);
            set => SetBool(RefreshKey, value);
        }

        获取或设置是否应允许刷新身份验证会话。
```
```
        public string GetString(string key)
        {
            return Items.TryGetValue(key, out string value) ? value : null;
        }

        从<see cref =“ Items” />集合中获取字符串值。
```
```
        public void SetString(string key, string value)
        {
            if (value != null)
            {
                Items[key] = value;
            }
            else
            {
                Items.Remove(key);
            }
        }

        在<see cref =“ Items” />集合中设置一个字符串值。
```
```
public T GetParameter<T>(string key)
            => Parameters.TryGetValue(key, out var obj) && obj is T value ? value : default;

            从<see cref =“ Parameters” />集合中获取参数。
```
```
        public void SetParameter<T>(string key, T value)
            => Parameters[key] = value;

            在<see cref =“ Parameters” />集合中设置参数值。
```
```
        protected bool? GetBool(string key)
        {
            if (Items.TryGetValue(key, out string value) && bool.TryParse(value, out bool boolValue))
            {
                return boolValue;
            }
            return null;
        }
        从<see cref =“ Items” />集合中获取布尔值。
```
```
        protected void SetBool(string key, bool? value)
        {
            if (value.HasValue)
            {
                Items[key] = value.GetValueOrDefault().ToString();
            }
            else
            {
                Items.Remove(key);
            }
        }
        在<see cref =“ Items” />集合中设置一个布尔值。
```
```
        protected DateTimeOffset? GetDateTimeOffset(string key)
        {
            if (Items.TryGetValue(key, out string value)
                && DateTimeOffset.TryParseExact(value, UtcDateTimeFormat, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset dateTimeOffset))
            {
                return dateTimeOffset;
            }
            return null;
        }
        从<see cref =“ Items” />集合中获取DateTimeOffset值。
```
```
       protected void SetDateTimeOffset(string key, DateTimeOffset? value)
        {
            if (value.HasValue)
            {
                Items[key] = value.GetValueOrDefault().ToString(UtcDateTimeFormat, CultureInfo.InvariantCulture);
            }
            else
            {
                Items.Remove(key);
            }
        }
        在<see cref =“ Items” />集合中设置DateTimeOffset值。
```
### AuthenticationTicket
    //包含用户身份信息以及其他身份验证状态
属性
```
public string AuthenticationScheme { get; private set; }

//获取身份验证类型。
```
```
public ClaimsPrincipal Principal { get; private set; }

//获取具有已验证用户身份的声明主体。
```
```
public AuthenticationProperties Properties { get; private set; }

身份验证会话的其他状态值。
```

### AuthenticationHttpContextExtensions
    //在HttpContext上公开身份验证的扩展方法。
```
        /// <summary>
        /// 使用<see cref =“ AuthenticationOptions.DefaultAuthenticateScheme” />方案进行身份验证的扩展方法。
        /// </summary>
        public static Task<AuthenticateResult> AuthenticateAsync(this HttpContext context) =>
            context.AuthenticateAsync(scheme: null);

        /// <summary>
        /// 身份验证的扩展方法。
        /// </summary>
        public static Task<AuthenticateResult> AuthenticateAsync(this HttpContext context, string scheme) =>
            context.RequestServices.GetRequiredService<IAuthenticationService>().AuthenticateAsync(context, scheme);

        /// <summary>
        /// Challenge的扩展方法
        /// </summary>
        public static Task ChallengeAsync(this HttpContext context, string scheme) =>
            context.ChallengeAsync(scheme, properties: null);

        /// <summary>
        ///使用<see cref =“ AuthenticationOptions.DefaultChallengeScheme” />方案进行身份验证的扩展方法。
        /// </summary>
        public static Task ChallengeAsync(this HttpContext context) =>
            context.ChallengeAsync(scheme: null, properties: null);

        /// <summary>
        /// Extension method for authenticate using the <see cref="AuthenticationOptions.DefaultChallengeScheme"/> scheme.
        /// </summary>
        public static Task ChallengeAsync(this HttpContext context, AuthenticationProperties properties) =>
            context.ChallengeAsync(scheme: null, properties: properties);

        /// <summary>
        /// Extension method for Challenge.
        /// </summary>
        public static Task ChallengeAsync(this HttpContext context, string scheme, AuthenticationProperties properties) =>
            context.RequestServices.GetRequiredService<IAuthenticationService>().ChallengeAsync(context, scheme, properties);

        /// <summary>
        /// Extension method for Forbid.
        /// </summary>
        public static Task ForbidAsync(this HttpContext context, string scheme) =>
            context.ForbidAsync(scheme, properties: null);

        /// <summary>
        /// Extension method for Forbid using the <see cref="AuthenticationOptions.DefaultForbidScheme"/> scheme..
        /// </summary>
        public static Task ForbidAsync(this HttpContext context) =>
            context.ForbidAsync(scheme: null, properties: null);

        /// <summary>
        /// Extension method for Forbid.
        /// </summary>
        public static Task ForbidAsync(this HttpContext context, AuthenticationProperties properties) =>
            context.ForbidAsync(scheme: null, properties: properties);

        /// <summary>
        /// Extension method for Forbid.
        /// </summary>
        public static Task ForbidAsync(this HttpContext context, string scheme, AuthenticationProperties properties) =>
            context.RequestServices.GetRequiredService<IAuthenticationService>().ForbidAsync(context, scheme, properties);

        /// <summary>
        /// Extension method for SignIn.
        /// </summary>
        public static Task SignInAsync(this HttpContext context, string scheme, ClaimsPrincipal principal) =>
            context.SignInAsync(scheme, principal, properties: null);

        /// <summary>
        /// Extension method for SignIn using the <see cref="AuthenticationOptions.DefaultSignInScheme"/>.
        /// </summary>
        public static Task SignInAsync(this HttpContext context, ClaimsPrincipal principal) =>
            context.SignInAsync(scheme: null, principal: principal, properties: null);

        /// <summary>
        /// Extension method for SignIn using the <see cref="AuthenticationOptions.DefaultSignInScheme"/>.
        /// </summary>
        public static Task SignInAsync(this HttpContext context, ClaimsPrincipal principal, AuthenticationProperties properties) =>
            context.SignInAsync(scheme: null, principal: principal, properties: properties);

        /// <summary>
        /// Extension method for SignIn.
        /// </summary>
        public static Task SignInAsync(this HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties) =>
            context.RequestServices.GetRequiredService<IAuthenticationService>().SignInAsync(context, scheme, principal, properties);

        /// <summary>
        /// Extension method for SignOut using the <see cref="AuthenticationOptions.DefaultSignOutScheme"/>.
        /// </summary>
        public static Task SignOutAsync(this HttpContext context) => context.SignOutAsync(scheme: null, properties: null);

        /// <summary>
        /// Extension method for SignOut using the <see cref="AuthenticationOptions.DefaultSignOutScheme"/>.
        /// </summary>
        public static Task SignOutAsync(this HttpContext context, AuthenticationProperties properties) => context.SignOutAsync(scheme: null, properties: properties);

        /// <summary>
        /// Extension method for SignOut.
        /// </summary>
        public static Task SignOutAsync(this HttpContext context, string scheme) => context.SignOutAsync(scheme, properties: null);

        /// <summary>
        /// Extension method for SignOut.
        /// </summary>
        public static Task SignOutAsync(this HttpContext context, string scheme, AuthenticationProperties properties) =>
            context.RequestServices.GetRequiredService<IAuthenticationService>().SignOutAsync(context, scheme, properties);

        /// <summary>
        /// 用于获取身份验证令牌的值的扩展方法。
        /// </summary>
        public static Task<string> GetTokenAsync(this HttpContext context, string scheme, string tokenName) =>
            context.RequestServices.GetRequiredService<IAuthenticationService>().GetTokenAsync(context, scheme, tokenName);

        /// <summary>
        /// 用于获取身份验证令牌的值的扩展方法。
        /// </summary>
        public static Task<string> GetTokenAsync(this HttpContext context, string tokenName) =>
            context.RequestServices.GetRequiredService<IAuthenticationService>().GetTokenAsync(context, tokenName);
```
### authenticationoptions
```
private readonly IList<AuthenticationSchemeBuilder> _schemes = new List<AuthenticationSchemeBuilder>();
```
```
//按添加顺序返回方案（对于请求处理优先级很重要）
public IEnumerable<AuthenticationSchemeBuilder> Schemes => _schemes;
```
```
//按名称映射方案。
 public IDictionary<string, AuthenticationSchemeBuilder> SchemeMap { get; } = new Dictionary<string, AuthenticationSchemeBuilder>(StringComparer.Ordinal);
```
```
        /// <summary>
        /// Adds an <see cref="AuthenticationScheme"/>.
        /// </summary>
        /// <param name="name">要添加的方案的名称.</param>
        /// <param name="configureBuilder">配置方案.</param>
  public void AddScheme(string name, Action<AuthenticationSchemeBuilder> configureBuilder)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }
            if (configureBuilder == null)
            {
                throw new ArgumentNullException(nameof(configureBuilder));
            }
            if (SchemeMap.ContainsKey(name))
            {
                throw new InvalidOperationException("Scheme already exists: " + name);
            }

            var builder = new AuthenticationSchemeBuilder(name);
            configureBuilder(builder);
            _schemes.Add(builder);
            SchemeMap[name] = builder;
        }
```
```
        /// <summary>
        /// Adds an <see cref="AuthenticationScheme"/>.
        /// </summary>
        /// <typeparam name="THandler"><see cref =“ IAuthenticationHandler” />负责该方案.</typeparam>
        /// <param name="name">要添加的方案的名称。</param>
        /// <param name="displayName">方案的显示名称.</param>
 public void AddScheme<THandler>(string name, string displayName) where THandler : IAuthenticationHandler
            => AddScheme(name, b =>
            {
                b.DisplayName = displayName;
                b.HandlerType = typeof(THandler);
            });
```
```
    /// <summary>
        /// 用作所有其他默认值的后备默认方案。
        /// </summary>
        public string DefaultScheme { get; set; }
```
```
        /// <summary>
        /// 由<see cref =“ IAuthenticationService.AuthenticateAsync（HttpContext，string）” />用作默认方案。
        /// </summary>
        public string DefaultAuthenticateScheme { get; set; }
```
```
      /// <summary>
        ///由<see cref =“ IAuthenticationService.SignInAsync（HttpContext，string，System.Security.Claims.ClaimsPrincipal，AuthenticationProperties）” />用作默认方案。
        /// </summary>
        public string DefaultSignInScheme { get; set; }
```
```
        /// <summary>
        /// 由<see cref =“ IAuthenticationService.SignOutAsync（HttpContext，string，AuthenticationProperties）” />用作默认方案。
        /// </summary>
        public string DefaultSignOutScheme { get; set; }
```
```
        /// <summary>
        /// 由<see cref =“ IAuthenticationService.ChallengeAsync（HttpContext，string，AuthenticationProperties）” />用作默认方案。
        /// </summary>
        public string DefaultChallengeScheme { get; set; }
```
```
        /// <summary>
        ///由<see cref =“ IAuthenticationService.ForbidAsync（HttpContext，string，AuthenticationProperties）” />用作默认方案。
        /// </summary>
        public string DefaultForbidScheme { get; set; }
```
```
        /// <summary>
        /// 如果为true，则尝试使用ClaimsPrincipal.Identity.IsAuthenticated = false时应抛出SignIn。
        /// </summary>
        public bool RequireAuthenticatedSignIn { get; set; } = true;
```
### AuthenticationScheme
    //AuthenticationSchemes将名称分配给特定的<see cref =“ IAuthenticationHandler” />
```
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="name">认证方案的名称.</param>
        /// <param name="displayName">认证方案的显示名称.</param>
        /// <param name="handlerType"><请参阅处理此方案的cref =“ IAuthenticationHandler” />类型。</param>
        public AuthenticationScheme(string name, string displayName, Type handlerType)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }
            if (handlerType == null)
            {
                throw new ArgumentNullException(nameof(handlerType));
            }
            if (!typeof(IAuthenticationHandler).IsAssignableFrom(handlerType))
            {
                throw new ArgumentException("handlerType must implement IAuthenticationHandler.");
            }

            Name = name;
            HandlerType = handlerType;
            DisplayName = displayName;
        }
```
```
        /// <summary>
        /// 认证方案的名称。
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// 方案的显示名称。 Null有效，并用于非面向用户的方案。
        /// </summary>
        public string DisplayName { get; }

        /// <summary>
        /// <see cref =“ IAuthenticationHandler” />类型可处理此方案。
        /// </summary>
        public Type HandlerType { get; }
```
### AuthenticationSchemeBuilder
    //用于构建<see cref =“ AuthenticationScheme” />。
```
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="name">The name of the scheme being built.</param>
        public AuthenticationSchemeBuilder(string name)
        {
            Name = name;
        }

        /// <summary>
        /// 正在构建的方案的名称。
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// 正在构建的方案的显示名称。
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        ///<see cref =“ IAuthenticationHandler” />类型负责此方案。
        /// </summary>
        public Type HandlerType { get; set; }

        /// <summary>
        /// 构建<see cref =“ AuthenticationScheme” />实例。
        /// </summary>
        /// <returns></returns>
        public AuthenticationScheme Build() => new AuthenticationScheme(Name, DisplayName, HandlerType);
```
### AuthenticationToken
    //代表令牌的名称/值。
```
        /// <summary>
        /// Name.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Value.
        /// </summary>
        public string Value { get; set; }
```
### AuthenticationTokenExtensions
    //在<see cref =“ AuthenticationProperties” />中存储身份验证令牌的扩展方法。
```
 private static string TokenNamesKey = ".TokenNames";
        private static string TokenKeyPrefix = ".Token.";
```
```
        /// <summary>
        /// 删除所有旧令牌后，存储一组身份验证令牌。
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        /// <param name="tokens">The tokens to store.</param>
        public static void StoreTokens(this AuthenticationProperties properties, IEnumerable<AuthenticationToken> tokens)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }
            if (tokens == null)
            {
                throw new ArgumentNullException(nameof(tokens));
            }

            // Clear old tokens first
            var oldTokens = properties.GetTokens();
            foreach (var t in oldTokens)
            {
                properties.Items.Remove(TokenKeyPrefix + t.Name);
            }
            properties.Items.Remove(TokenNamesKey);

            var tokenNames = new List<string>();
            foreach (var token in tokens)
            {
                // REVIEW: should probably check that there are no ; in the token name and throw or encode
                tokenNames.Add(token.Name);
                properties.Items[TokenKeyPrefix+token.Name] = token.Value;
            }
            if (tokenNames.Count > 0)
            {
                properties.Items[TokenNamesKey] = string.Join(";", tokenNames.ToArray());
            }
        }
```
```
        /// <summary>
        /// R返回令牌的值。
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        /// <param name="tokenName">The token name.</param>
        /// <returns>The token value.</returns>
        public static string GetTokenValue(this AuthenticationProperties properties, string tokenName)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }
            if (tokenName == null)
            {
                throw new ArgumentNullException(nameof(tokenName));
            }

            var tokenKey = TokenKeyPrefix + tokenName;
            return properties.Items.ContainsKey(tokenKey)
                ? properties.Items[tokenKey]
                : null;
        }
```
```
        public static bool UpdateTokenValue(this AuthenticationProperties properties, string tokenName, string tokenValue)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }
            if (tokenName == null)
            {
                throw new ArgumentNullException(nameof(tokenName));
            }

            var tokenKey = TokenKeyPrefix + tokenName;
            if (!properties.Items.ContainsKey(tokenKey))
            {
                return false;
            }
            properties.Items[tokenKey] = tokenValue;
            return true;
        }
```
```
        /// <summary>
        /// 返回属性中包含的所有AuthenticationToken。
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        /// <returns>The authentication tokens.</returns>
        public static IEnumerable<AuthenticationToken> GetTokens(this AuthenticationProperties properties)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            var tokens = new List<AuthenticationToken>();
            if (properties.Items.ContainsKey(TokenNamesKey))
            {
                var tokenNames = properties.Items[TokenNamesKey].Split(';');
                foreach (var name in tokenNames)
                {
                    var token = properties.GetTokenValue(name);
                    if (token != null)
                    {
                        tokens.Add(new AuthenticationToken { Name = name, Value = token });
                    }
                }
            }

            return tokens;
        }
```
```
        /// <summary>
        /// 用于获取身份验证令牌的值的扩展方法。
        /// </summary>
        /// <param name="auth">The <see cref="IAuthenticationService"/>.</param>
        /// <param name="context">The <see cref="HttpContext"/> context.</param>
        /// <param name="tokenName">The name of the token.</param>
        /// <returns>The value of the token.</returns>
        public static Task<string> GetTokenAsync(this IAuthenticationService auth, HttpContext context, string tokenName)
            => auth.GetTokenAsync(context, scheme: null, tokenName: tokenName);
```
```
        /// <summary>
        ///用于获取身份验证令牌的值的扩展方法。
        /// </summary>
        /// <param name="auth">The <see cref="IAuthenticationService"/>.</param>
        /// <param name="context">The <see cref="HttpContext"/> context.</param>
        /// <param name="scheme">The name of the authentication scheme.</param>
        /// <param name="tokenName">The name of the token.</param>
        /// <returns>The value of the token.</returns>
        public static async Task<string> GetTokenAsync(this IAuthenticationService auth, HttpContext context, string scheme, string tokenName)
        {
            if (auth == null)
            {
                throw new ArgumentNullException(nameof(auth));
            }
            if (tokenName == null)
            {
                throw new ArgumentNullException(nameof(tokenName));
            }

            var result = await auth.AuthenticateAsync(context, scheme);
            return result?.Properties?.GetTokenValue(tokenName);
        }
```