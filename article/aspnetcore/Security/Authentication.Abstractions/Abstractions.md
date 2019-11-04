|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AuthenticateResult](#authenticateresult)
* [AuthenticationProperties](#authenticationproperties)
* [文本](#文本)


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