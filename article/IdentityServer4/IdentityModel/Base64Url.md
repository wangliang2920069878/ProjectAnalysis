|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [Base64Url](#base64url)
* [ClaimComparer](#claimcomparer)
* [CryptoRandom](#cryptorandom)
* [CryptoRandom](#cryptorandom)
* [DateTimeExtensions](#datetimeextensions)
* [Identity](#identity)
* [JwtClaimTypes](#jwtclaimtypes)
* [OidcConstants](#oidcconstants)
* [Principal](#principal)
* [StringExtensions](#stringextensions)
* [TimeConstantComparer](#timeconstantcomparer)
###
```
    /// <summary>
    /// Base64Url编码器/解码器
    /// </summary>
    public static class Base64Url
    {
        /// <summary>
        /// 对指定的字节数组进行编码。
        /// </summary>
        /// <param name="arg">The argument.</param>
        /// <returns></returns>
        public static string Encode(byte[] arg)
        {
            var s = Convert.ToBase64String(arg); // Standard base64 encoder
            
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            
            return s;
        }

        /// <summary>
        /// 解码指定的字符串。
        /// </summary>
        /// <param name="arg">The argument.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception">Illegal base64url string!</exception>
        public static byte[] Decode(string arg)
        {
            var s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default: throw new Exception("Illegal base64url string!");
            }
            
            return Convert.FromBase64String(s); // Standard base64 decoder
        }
    }
```

### ClaimComparer
```
    /// <summary>
    /// 比较Claim的两个实例  一般用于字典key 的比较
    /// </summary>
    public class ClaimComparer : EqualityComparer<Claim>
    {
        /// <summary>
        /// Claim比较选项
        /// </summary>
        public class Options
        {
            /// <summary>
            /// 指定是否考虑发行人
            /// </summary>
            public bool IgnoreIssuer { get; set; } = false;

            /// <summary>
            ///指定声明和发行者的值比较是否应区分大小写
            /// </summary>
            public bool IgnoreValueCase { get; set; } = false;
        }

        private readonly Options _options = new Options();

        /// <summary>
        /// Initializes a new instance of the <see cref="ClaimComparer"/> class with default options.
        /// </summary>
        public ClaimComparer()
        { }

        /// <summary>
        /// 使用给定的比较选项初始化<see cref =“ ClaimComparer” />类的新实例。
        /// </summary>
        /// <param name="options">Comparison options.</param>
        public ClaimComparer(Options options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <inheritdoc/>
        public override bool Equals(Claim x, Claim y)
        {
            if (x == null && y == null) return true;
            if (x == null && y != null) return false;
            if (x != null && y == null) return false;

            StringComparison valueComparison = StringComparison.Ordinal;
            if (_options.IgnoreValueCase == true) valueComparison = StringComparison.OrdinalIgnoreCase;

            var equal = (String.Equals(x.Type, y.Type, StringComparison.OrdinalIgnoreCase) &&
                         String.Equals(x.Value, y.Value, valueComparison) &&
                         String.Equals(x.ValueType, y.ValueType, StringComparison.Ordinal));


            if (_options.IgnoreIssuer)
            {
                return equal;
            }
            else
            {
                return (equal && String.Equals(x.Issuer, y.Issuer, valueComparison));
            }
        }

        /// <inheritdoc/>
        public override int GetHashCode(Claim claim)
        {
            if (claim is null) return 0;

            int typeHash = claim.Type?.ToLowerInvariant().GetHashCode() ?? 0 ^ claim.ValueType?.GetHashCode() ?? 0;
            int valueHash;
            int issuerHash;

            if (_options.IgnoreValueCase)
            {
                valueHash = claim.Value?.ToLowerInvariant().GetHashCode() ?? 0;
                issuerHash = claim.Issuer?.ToLowerInvariant().GetHashCode() ?? 0;
            }
            else
            {
                valueHash = claim.Value?.GetHashCode() ?? 0;
                issuerHash = claim.Issuer?.GetHashCode() ?? 0;
            }

            if (_options.IgnoreIssuer)
            {
                return typeHash ^ valueHash;
                
            }
            else
            {
                return typeHash ^ valueHash ^ issuerHash;
            }
        }
    }
```
### CryptoRandom
```
    /// <summary>
    ///模仿.NET Framework中标准Random类的类，但在内部使用随机数生成器。
    /// </summary>
    public class CryptoRandom : Random
    {
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
        private readonly byte[] _uint32Buffer = new byte[4];

        /// <summary>
        ///唯一ID的输出格式
        /// </summary>
        public enum OutputFormat
        {
            /// <summary>
            /// URL-safe Base64
            /// </summary>
            Base64Url,
            /// <summary>
            /// Base64
            /// </summary>
            Base64,
            /// <summary>
            /// Hex
            /// </summary>
            Hex
        }

        /// <summary>
        /// 创建一个随机密钥字节数组。
        /// </summary>
        /// <param name="length">The length.</param>
        /// <returns></returns>
        public static byte[] CreateRandomKey(int length)
        {
            var bytes = new byte[length];
            Rng.GetBytes(bytes);

            return bytes;
        }

        /// <summary>
        ///创建一个URL安全的唯一标识符。
        /// </summary>
        /// <param name="length">The length.</param>
        /// <param name="format">The output format</param>
        /// <returns></returns>
        public static string CreateUniqueId(int length = 32, OutputFormat format = OutputFormat.Base64Url)
        {
            var bytes = CreateRandomKey(length);
            
            switch (format)
            {
                case OutputFormat.Base64Url:
                    return Base64Url.Encode(bytes);
                case OutputFormat.Base64:
                    return Convert.ToBase64String(bytes);
                case OutputFormat.Hex:
                    return BitConverter.ToString(bytes).Replace("-", "");
                default:
                    throw new ArgumentException("Invalid output format", nameof(format));
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptoRandom"/> class.
        /// </summary>
        public CryptoRandom() { }

        /// <summary>
        /// 初始化<see cref =“ CryptoRandom” />类的新实例。
        /// </summary>
        /// <param name="ignoredSeed">种子（忽略）</param>
        public CryptoRandom(Int32 ignoredSeed) { }

        /// <summary>
        /// 返回一个非负的随机数。
        /// </summary>
        /// <returns>
        ///一个大于或等于零且小于<参见cref =“ F：System.Int32.MaxValue” />的32位有符号整数。
        /// </returns>
        public override Int32 Next()
        {
            Rng.GetBytes(_uint32Buffer);
            return BitConverter.ToInt32(_uint32Buffer, 0) & 0x7FFFFFFF;
        }

        /// <summary>
        /// 返回小于指定最大值的非负随机数。
        /// </summary>
        /// <param name="maxValue">要生成的随机数的排他上限。 <paramref name =“ maxValue” />必须大于或等于零。</param>
        /// <returns>
        ///一个大于或等于零且小于<paramref name =“ maxValue” />的32位有符号整数； 也就是说，返回值的范围通常包括零，但不包括<paramref name =“ maxValue” />。 但是，如果<paramref name =“ maxValue” />等于零，则返回<paramref name =“ maxValue” />。
        /// </returns>
        /// <exception cref="T:System.ArgumentOutOfRangeException">
        /// 	<paramref name="maxValue"/> is less than zero.
        /// </exception>
        public override Int32 Next(Int32 maxValue)
        {
            if (maxValue < 0) throw new ArgumentOutOfRangeException(nameof(maxValue));
            return Next(0, maxValue);
        }

        /// <summary>
        /// 返回指定范围内的随机数。
        /// </summary>
        /// <param name="minValue">返回的随机数（含）下限。</param>
        /// <param name="maxValue">返回的随机数的排他上限。 <paramref name =“ maxValue” />必须大于或等于<paramref name =“ minValue” />.</param>
        /// <returns>
        ///一个大于或等于<paramref name =“ minValue” />且小于<paramref name =“ maxValue” />的32位带符号整数； 也就是说，返回值的范围包括<paramref name =“ minValue” />，但不包括<paramref name =“ maxValue” />。 如果<paramref name =“ minValue” />等于<paramref name =“ maxValue” />，则返回<paramref name =“ minValue” />。
        /// </returns>
        /// <exception cref="T:System.ArgumentOutOfRangeException">
        /// 	<paramref name="minValue"/> is greater than <paramref name="maxValue"/>.
        /// </exception>
        public override Int32 Next(Int32 minValue, Int32 maxValue)
        {
            if (minValue > maxValue) throw new ArgumentOutOfRangeException(nameof(minValue));
            if (minValue == maxValue) return minValue;
            Int64 diff = maxValue - minValue;

            while (true)
            {
                Rng.GetBytes(_uint32Buffer);
                UInt32 rand = BitConverter.ToUInt32(_uint32Buffer, 0);

                Int64 max = (1 + (Int64)UInt32.MaxValue);
                Int64 remainder = max % diff;
                if (rand < max - remainder)
                {
                    return (Int32)(minValue + (rand % diff));
                }
            }
        }

        /// <summary>
        /// 返回0.0到1.0之间的随机数。
        /// </summary>
        /// <returns>
        /// 大于或等于0.0且小于1.0的双精度浮点数。
        /// </returns>
        public override double NextDouble()
        {
            Rng.GetBytes(_uint32Buffer);
            UInt32 rand = BitConverter.ToUInt32(_uint32Buffer, 0);
            return rand / (1.0 + UInt32.MaxValue);
        }

        /// <summary>
        /// 用随机数填充指定字节数组的元素。
        /// </summary>
        /// <param name="buffer">包含随机数的字节数组.</param>
        /// <exception cref="T:System.ArgumentNullException">
        /// 	<paramref name="buffer"/> is null.
        /// </exception>
        public override void NextBytes(byte[] buffer)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            Rng.GetBytes(buffer);
        }
    }
```
### DateTimeExtensions
```
    /// <summary>
    /// 用于将纪元/ unix时间转换为DateTime和DateTimeOffset的扩展
    /// </summary>
    public static class DateTimeExtensions
    {
        /// <summary>
        /// 将给定的日期值转换为纪元时间。
        /// </summary>
        public static long ToEpochTime(this DateTime dateTime)
        {
            var date = dateTime.ToUniversalTime();
            var ticks = date.Ticks - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).Ticks;
            var ts = ticks / TimeSpan.TicksPerSecond;
            return ts;
        }

        /// <summary>
        ///用<see cref =“ DateTimeKind.Utc” />种类将给定的时间转换为<see cref =“ DateTime” />。
        /// </summary>
        public static DateTime ToDateTimeFromEpoch(this long date)
        {
            var timeInTicks = date * TimeSpan.TicksPerSecond;
            return new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddTicks(timeInTicks);
        }
    }
```
### Identity
```
    /// <summary>
    /// 帮助创建ClaimsIdentity
    /// </summary>
    public static class Identity
    {
        /// <summary>
        ///创建一个匿名声明身份。
        /// </summary>
        /// <value>
        /// The anonymous.
        /// </value>
        public static ClaimsIdentity Anonymous
        {
            get
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, "")
                };

                return new ClaimsIdentity(claims);
            }
        }

        /// <summary>
        /// 使用指定的身份验证类型和声明创建ClaimsIdentity。
        /// </summary>
        /// <param name="authenticationType">认证类型。</param>
        /// <param name="claims">The claims.</param>
        /// <returns></returns>
        public static ClaimsIdentity Create(string authenticationType, params Claim[] claims)
        {
            return new ClaimsIdentity(claims, authenticationType, JwtClaimTypes.Name, JwtClaimTypes.Role);
        }

        /// <summary>
        /// 根据X509证书中找到的信息创建ClaimsIdentity。
        /// </summary>
        /// <param name="certificate">证书.</param>
        /// <param name="authenticationType">认证类型.</param>
        /// <param name="includeAllClaims">如果设置为<c> true </ c> [包括所有声明].</param>
        /// <returns></returns>
        public static ClaimsIdentity CreateFromCertificate(X509Certificate2 certificate, string authenticationType = "X.509", bool includeAllClaims = false)
        {
            var claims = new List<Claim>();
            var issuer = certificate.Issuer;

            claims.Add(new Claim("issuer", issuer));

            var thumbprint = certificate.Thumbprint;
            claims.Add(new Claim(ClaimTypes.Thumbprint, thumbprint, ClaimValueTypes.Base64Binary, issuer));

            var name = certificate.SubjectName.Name;
            if (name.IsPresent())
            {
                claims.Add(new Claim(ClaimTypes.X500DistinguishedName, name, ClaimValueTypes.String, issuer));
            }

            if (includeAllClaims)
            {
                name = certificate.SerialNumber;
                if (name.IsPresent())
                {
                    claims.Add(new Claim(ClaimTypes.SerialNumber, name, ClaimValueTypes.String, issuer));
                }

                name = certificate.GetNameInfo(X509NameType.DnsName, false);
                if (name.IsPresent())
                {
                    claims.Add(new Claim(ClaimTypes.Dns, name, ClaimValueTypes.String, issuer));
                }

                name = certificate.GetNameInfo(X509NameType.SimpleName, false);
                if (name.IsPresent())
                {
                    claims.Add(new Claim(ClaimTypes.Name, name, ClaimValueTypes.String, issuer));
                }

                name = certificate.GetNameInfo(X509NameType.EmailName, false);
                if (name.IsPresent())
                {
                    claims.Add(new Claim(ClaimTypes.Email, name, ClaimValueTypes.String, issuer));
                }

                name = certificate.GetNameInfo(X509NameType.UpnName, false);
                if (name.IsPresent())
                {
                    claims.Add(new Claim(ClaimTypes.Upn, name, ClaimValueTypes.String, issuer));
                }

                name = certificate.GetNameInfo(X509NameType.UrlName, false);
                if (name.IsPresent())
                {
                    claims.Add(new Claim(ClaimTypes.Uri, name, ClaimValueTypes.String, issuer));
                }
            }

            return new ClaimsIdentity(claims, authenticationType);
        }
    }
```
### JwtClaimTypes
```
    /// <summary>
    /// 常用的Claim类型
    /// </summary>
    public static class JwtClaimTypes
    {
        /// <summary>发行方最终用户的唯一标识符。</summary>
        public const string Subject = "sub";

        /// <summary>最终用户的可显示全名，包括所有名称部分，可能包括标题和后缀，根据最终用户的语言环境和首选项进行排序。</summary>
        public const string Name = "name";

        /// <summary>给出最终用户的名字或名字。 请注意，在某些文化中，人们可以使用多个名字。 所有名称都可以显示，名称之间用空格字符分隔。</summary>
        public const string GivenName = "given_name";

        /// <summary>最终用户的姓氏或姓氏。 请注意，在某些文化中，人们可以有多个姓氏，也可以没有姓氏。 所有名称都可以显示，名称之间用空格字符分隔。</summary>
        public const string FamilyName = "family_name";

        /// <summary>最终用户的中间名。 请注意，在某些文化中，人们可以有多个中间名。 所有名称都可以显示，名称之间用空格字符分隔。 另请注意，在某些文化中，不使用中间名。</summary>
        public const string MiddleName = "middle_name";

        /// <summary>最终用户的临时名称，该临时名称可能与给定名称相同或不同。 例如，可能会返回Mike的昵称值和Michael的named_name值.</summary>
        public const string NickName = "nickname";

        /// <summary>最终用户希望在RP上引用的简写名称，例如janedoe或j.doe。 该值可以是任何有效的JSON字符串，包括特殊字符，例如@，/或空格。 依赖方一定不能依赖此唯一值</summary>
        /// <remarks>如http://openid.net/specs/openid-connect-basic-1_0-32.html#ClaimStability中所述，RP绝对不能依赖此值的唯一性</remarks>
        public const string PreferredUserName = "preferred_username";

        /// <summary>最终用户的个人资料页面的URL。 该网页的内容应与最终用户有关。</summary>
        public const string Profile = "profile";

        /// <summary>最终用户个人资料图片的URL。 该URL必须引用图像文件（例如，PNG，JPEG或GIF图像文件），而不是包含图像的网页。</summary>
        /// <remarks>请注意，此URL应该专门引用适合描述最终用户时显示的最终用户的个人资料照片，而不是最终用户拍摄的任意照片。</remarks>
        public const string Picture = "picture";

        /// <summary>最终用户的网页或博客的URL。 该网页应包含最终用户或最终用户所属组织发布的信息。</summary>
        public const string WebSite = "website";

        /// <summary>最终用户的首选电子邮件地址。 它的值必须符合RFC 5322 [RFC5322] addr-spec语法。 依赖方一定不能依赖此唯一值</summary>
        public const string Email = "email";

        /// <summary>如果已验证最终用户的电子邮件地址，则为“ true”； 否则为“假”。</summary>
        ///  <remarks>当此Claim Value为“ true”时，这意味着OP采取了肯定的措施来确保此电子邮件地址在执行验证时由最终用户控制。 验证电子邮件地址的方法是特定于上下文的，并且取决于各方在其中进行操作的信任框架或合同协议。</remarks>
        public const string EmailVerified = "email_verified";

        /// <summary>最终用户的性别。 本规范定义的值为“女性”和“男性”。 当两个定义的值都不适用时，可以使用其他值。</summary>
        public const string Gender = "gender";

        /// <summary>最终用户的生日，以ISO 8601：2004 [ISO8601-2004] YYYY-MM-DD格式表示。 年份可以为0000，表示已省略。 仅代表年份，允许使用YYYY格式。 请注意，根据基础平台的日期相关功能，仅提供年份可能会导致月份和日期的变化，因此实施者需要考虑此因素才能正确处理日期。</summary>
        public const string BirthDate = "birthdate";

        /// <summary>来自时区数据库（http://www.twinsun.com/tz/tz-link.htm）的字符串，表示最终用户的时区。 例如，欧洲/巴黎或美国/洛杉矶.</summary>
        public const string ZoneInfo = "zoneinfo";

        /// <summary>最终用户的语言环境，用BCP47 [RFC5646]语言标记表示。 这通常是小写的ISO 639-1 Alpha-2 [ISO639-1]语言代码和大写的ISO 3166-1 Alpha-2 [ISO3166-1]国家/地区代码，以短划线分隔。 例如，en-US或fr-CA。 作为兼容性说明，某些实现使用下划线作为分隔符而不是破折号，例如，en_US。 依赖方也可以选择接受此语言环境语法.</summary>
        public const string Locale = "locale";

        /// <summary>最终用户的首选电话号码。 建议将E.164（https://www.itu.int/rec/T-REC-E.164/e）作为本声明的格式，例如+1（425）555-1212或+56（ 2）6872400。如果电话号码包含分机号，建议使用RFC 3966 [RFC3966]分机语法表示该分机，例如+1（604）555-1234; ext = 5678。</summary>
        public const string PhoneNumber = "phone_number";

        /// <summary>如果最终用户的电话号码已经过验证，则为true；否则为true。 否则为假。 如果此Claim Value为true，则表示OP采取了肯定的措施以确保该电话号码在执行验证时由最终用户控制.</summary>
        /// <remarks>The means by which a phone number is verified is context-specific, and dependent upon the trust framework or contractual agreements within which the parties are operating. When true, the phone_number Claim MUST be in E.164 format and any extensions MUST be represented in RFC 3966 format.</remarks>
        public const string PhoneNumberVerified = "phone_number_verified";

        /// <summary>最终用户的首选邮政地址。 地址成员的值是JSON结构，其中包含http://openid.net/specs/openid-connect-basic-1_0-32.html#AddressClaim中定义的部分或全部成员</summary>
        public const string Address = "address";

        /// <summary>该ID令牌的目标受众。 它必须包含依赖方的OAuth 2.0 client_id作为受众值。 它也可以包含其他受众的标识符。 通常，aud值是区分大小写的字符串数组。 在只有一个听众的特殊情况下，aud值可以是单个区分大小写的字符串。</summary>
        public const string Audience = "aud";

        /// <summary>响应的颁发者的颁发者标识符。 iss值是区分大小写的URL，使用https方案，其中包含方案，主机以及端口号和路径组成部分（可选），不包含查询或片段组成部分。</summary>
        public const string Issuer = "iss";

        /// <summary>不得接受JWT进行处理的时间，指定为从1970-01-01T0：0：0Z开始的秒数</summary>
        public const string NotBefore = "nbf";

        /// <summary>exp（到期时间）声明标识必须在其上或之后不接受令牌进行处理的到期时间，指定为从1970-01-01T0：0：0Z开始的秒数</summary>
        public const string Expiration = "exp";

        /// <summary>最终用户信息的最新更新时间。 它的值是一个JSON数字，代表从1970-01-01T0：0：0Z（以UTC度量）到日期/时间为止的秒数。.</summary>
        public const string UpdatedAt = "updated_at";

        /// <summary>iat（在发出）声明标识JWT的发布时间，指定为从1970-01-01T0：0：0Z开始的秒数。</summary>
        public const string IssuedAt = "iat";

        /// <summary>身份验证方法参考。 字符串的JSON数组，是身份验证中使用的身份验证方法的标识符。</summary>
        public const string AuthenticationMethod = "amr";

        /// <summary>会话标识符。 这表示在RP上OP到登录的最终用户的用户代理或设备的会话。 它的内容对于OP是唯一的，对于RP是不透明的.</summary>
        public const string SessionId = "sid";

        /// <summary>
        ///身份验证上下文类参考。一个字符串，它指定一个身份验证上下文类参考值，该值标识执行的身份验证所满足的身份验证上下文类。
        ///值“ 0”表示最终用户身份验证不符合ISO / IEC 29115级别1的要求。
        ///例如，使用长期存在的浏览器cookie进行身份验证是一个适合使用“级别0”的示例。
        ///不应使用0级身份验证来授权访问任何货币价值的任何资源。
        ///（这对应于OpenID 2.0 PAPE nist_auth_level0。）
        ///绝对URI或RFC 6711注册名称应用作acr值；注册名称不得以不同于注册名称的含义使用。
        ///使用此声明的各方将需要就所使用的值的含义达成共识，这些值可能是上下文相关的。
        /// acr值是区分大小写的字符串。
        /// </summary>
        public const string AuthenticationContextClassReference = "acr";

        /// <summary>最终用户身份验证发生的时间。 它的值是一个JSON数字，代表从1970-01-01T0：0：0Z（以UTC度量）到日期/时间为止的秒数。 当发出max_age请求或将auth_time请求为基本声明时，则需要此声明； 否则，它是可选的。</summary>
        public const string AuthenticationTime = "auth_time";

        /// <summary>发行ID令牌的一方。 如果存在，则必须包含该参与方的OAuth 2.0客户端ID。 仅当ID令牌具有单个受众值并且该受众不同于授权方时，才需要此声明。 即使授权方与唯一的听众相同，也可以包括在内。 azp值是区分大小写的字符串，其中包含StringOrURI值。</summary>
        public const string AuthorizedParty = "azp";

        /// <summary> 访问令牌哈希值。 其值是access_token值的ASCII表示形式的八位字节的哈希的最左半部分的base64url编码，其中使用的哈希算法是ID令牌的JOSE标头的alg标头参数中使用的哈希算法。 例如，如果alg是RS256，则用SHA-256对access_token值进行哈希处理，然后采用最左边的128位并用base64url对其进行编码。 at_hash值是区分大小写的字符串.</summary>
        public const string AccessTokenHash = "at_hash";

        /// <summary>代码哈希值。 它的值是代码值的ASCII表示形式的八位字节的哈希的最左半部分的base64url编码，其中使用的哈希算法是ID令牌的JOSE标头的alg标头参数中使用的哈希算法。 例如，如果alg是HS512，则用SHA-512哈希代码值，然后采用最左边的256位并用base64url对其进行编码。 c_hash值是区分大小写的字符串.</summary>
        public const string AuthorizationCodeHash = "c_hash";

        /// <summary>状态哈希值。 它的值是状态值的ASCII表示形式的八位字节的最左半部分哈希的base64url编码，其中使用的哈希算法是ID令牌的JOSE标头的alg标头参数中使用的哈希算法。 例如，如果alg是HS512，则用SHA-512哈希代码值，然后采用最左边的256位并用base64url对其进行编码。 c_hash值是区分大小写的字符串。</summary>
        public const string StateHash = "s_hash";

        /// <summary>字符串值，用于将客户端会话与ID令牌相关联，并减轻重放攻击。 该值将未经修改地从身份验证请求传递到ID令牌。 如果在ID令牌中存在，则客户端必须验证现时声明值等于在身份验证请求中发送的现时参数值。 如果在认证请求中存在，授权服务器必须在ID令牌中包括一个随机数声明，该声明值是在认证请求中发送的随机数值。 授权服务器不应对所使用的随机数进行任何其他处理。 随机数值是区分大小写的字符串.</summary>
        public const string Nonce = "nonce";

        /// <summary>JWT ID。 令牌的唯一标识符，可用于防止令牌的重复使用。 这些令牌只能使用一次，除非双方之间协商了重用条件； 任何此类协商均超出本规范的范围。</summary>
        public const string JwtId = "jti";

        /// <summary>定义一组事件语句，每个事件语句可以添加其他声明以完全描述已发生的单个逻辑事件.</summary>
        public const string Events = "events";

        /// <summary>OAuth 2.0客户端标识符在授权服务器上有效。</summary>
        public const string ClientId = "client_id";

        /// <summary>OpenID Connect请求必须包含“ openid”作用域值。 如果不存在openid范围值，则完全不确定行为。 可能存在其他范围值。 实现中无法理解的范围值应被忽略.</summary>
        public const string Scope = "scope";

        /// <summary>“ act”（actor）声明提供了一种JWT中的方法，用于表示已发生委派并标识已授权其代理的代理方。“ act”声明值是JSON对象，并且JSON对象中的成员是声明。 识别演员。 组成“行为”声明的声明标识并可能提供有关演员的其他信息.</summary>
        public const string Actor = "act";

        /// <summary>“ may_act”主张声明一个当事方被授权成为演员并代表另一方行事。 声明值是一个JSON对象，并且JSON对象中的成员是声明，该声明标识被断言可以胜任包含声明的JWT标识的参与方的当事人。</summary>
        public const string MayAct = "may_act";

        /// <summary>
        /// 标识符
        /// </summary>
        public const string Id = "id";

        /// <summary>
        /// 身份提供者
        /// </summary>
        public const string IdentityProvider = "idp";

        /// <summary>
        /// 角色
        /// </summary>
        public const string Role = "role";

        /// <summary>
        /// 参考令牌标识符
        /// </summary>
        public const string ReferenceTokenId = "reference_token_id";

        /// <summary>
        /// 确认
        /// </summary>
        public const string Confirmation = "cnf";
    }
```
### OidcConstants
```
    public static class OidcConstants
    {
        public static class AuthorizeRequest
        {
            public const string Scope = "scope";
            public const string ResponseType = "response_type";
            public const string ClientId = "client_id";
            public const string RedirectUri = "redirect_uri";
            public const string State = "state";
            public const string ResponseMode = "response_mode";
            public const string Nonce = "nonce";
            public const string Display = "display";
            public const string Prompt = "prompt";
            public const string MaxAge = "max_age";
            public const string UiLocales = "ui_locales";
            public const string IdTokenHint = "id_token_hint";
            public const string LoginHint = "login_hint";
            public const string AcrValues = "acr_values";
            public const string CodeChallenge = "code_challenge";
            public const string CodeChallengeMethod = "code_challenge_method";
            public const string Request = "request";
            public const string RequestUri = "request_uri";
        }

        public static class AuthorizeErrors
        {
            // OAuth2 errors
            public const string InvalidRequest = "invalid_request";
            public const string UnauthorizedClient = "unauthorized_client";
            public const string AccessDenied = "access_denied";
            public const string UnsupportedResponseType = "unsupported_response_type";
            public const string InvalidScope = "invalid_scope";
            public const string ServerError = "server_error";
            public const string TemporarilyUnavailable = "temporarily_unavailable";

            // OIDC errors
            public const string InteractionRequired = "interaction_required";
            public const string LoginRequired = "login_required";
            public const string AccountSelectionRequired = "account_selection_required";
            public const string ConsentRequired = "consent_required";
            public const string InvalidRequestUri = "invalid_request_uri";
            public const string InvalidRequestObject = "invalid_request_object";
            public const string RequestNotSupported = "request_not_supported";
            public const string RequestUriNotSupported = "request_uri_not_supported";
            public const string RegistrationNotSupported = "registration_not_supported";
        }

        public static class AuthorizeResponse
        {
            public const string Scope = "scope";
            public const string Code = "code";
            public const string AccessToken = "access_token";
            public const string ExpiresIn = "expires_in";
            public const string TokenType = "token_type";
            public const string RefreshToken = "refresh_token";
            public const string IdentityToken = "id_token";
            public const string State = "state";
            public const string Error = "error";
            public const string ErrorDescription = "error_description";
        }

        public static class DeviceAuthorizationResponse
        {
            public const string DeviceCode = "device_code";
            public const string UserCode = "user_code";
            public const string VerificationUri = "verification_uri";
            public const string VerificationUriComplete = "verification_uri_complete";
            public const string ExpiresIn = "expires_in";
            public const string Interval = "interval";
        }

        public static class EndSessionRequest
        {
            public const string IdTokenHint = "id_token_hint";
            public const string PostLogoutRedirectUri = "post_logout_redirect_uri";
            public const string State = "state";
            public const string Sid = "sid";
            public const string Issuer = "iss";
        }

        public static class TokenRequest
        {
            public const string GrantType = "grant_type";
            public const string RedirectUri = "redirect_uri";
            public const string ClientId = "client_id";
            public const string ClientSecret = "client_secret";
            public const string ClientAssertion = "client_assertion";
            public const string ClientAssertionType = "client_assertion_type";
            public const string Assertion = "assertion";
            public const string Code = "code";
            public const string RefreshToken = "refresh_token";
            public const string Scope = "scope";
            public const string UserName = "username";
            public const string Password = "password";
            public const string CodeVerifier = "code_verifier";
            public const string TokenType = "token_type";
            public const string Algorithm = "alg";
            public const string Key = "key";
            public const string DeviceCode = "device_code";

            // token exchange
            public const string Resource = "resource";
            public const string Audience = "audience";
            public const string RequestedTokenType = "requested_token_type";
            public const string SubjectToken = "subject_token";
            public const string SubjectTokenType = "subject_token_type";
            public const string ActorToken = "actor_token";
            public const string ActorTokenType = "actor_token_type";
        }

        public static class TokenRequestTypes
        {
            public const string Bearer = "bearer";
            public const string Pop = "pop";
        }

        public static class TokenErrors
        {
            public const string InvalidRequest = "invalid_request";
            public const string InvalidClient = "invalid_client";
            public const string InvalidGrant = "invalid_grant";
            public const string UnauthorizedClient = "unauthorized_client";
            public const string UnsupportedGrantType = "unsupported_grant_type";
            public const string UnsupportedResponseType = "unsupported_response_type";
            public const string InvalidScope = "invalid_scope";
            public const string AuthorizationPending = "authorization_pending";
            public const string AccessDenied = "access_denied";
            public const string SlowDown = "slow_down";
            public const string ExpiredToken = "expired_token";
        }

        public static class TokenResponse
        {
            public const string AccessToken = "access_token";
            public const string ExpiresIn = "expires_in";
            public const string TokenType = "token_type";
            public const string RefreshToken = "refresh_token";
            public const string IdentityToken = "id_token";
            public const string Error = "error";
            public const string ErrorDescription = "error_description";
            public const string BearerTokenType = "Bearer";
            public const string IssuedTokenType = "issued_token_type";
            public const string Scope = "scope";
        }

        public static class TokenIntrospectionRequest
        {
            public const string Token = "token";
            public const string TokenTypeHint = "token_type_hint";
        }

        public static class RegistrationResponse
        {
            public const string Error = "error";
            public const string ErrorDescription = "error_description";
            public const string ClientId = "client_id";
            public const string ClientSecret = "client_secret";
            public const string RegistrationAccessToken = "registration_access_token";
            public const string RegistrationClientUri = "registration_client_uri";
            public const string ClientIdIssuedAt = "client_id_issued_at";
            public const string ClientSecretExpiresAt = "client_secret_expires_at";
        }

        public static class ClientMetadata
        {
            public const string RedirectUris = "redirect_uris";
            public const string ResponseTypes = "response_types";
            public const string GrantTypes = "grant_types";
            public const string ApplicationType = "application_type";
            public const string Contacts = "contacts";
            public const string ClientName = "client_name";
            public const string LogoUri = "logo_uri";
            public const string ClientUri = "client_uri";
            public const string PolicyUri = "policy_uri";
            public const string TosUri = "tos_uri";
            public const string JwksUri = "jwks_uri";
            public const string Jwks = "jwks";
            public const string SectorIdentifierUri = "sector_identifier_uri";
            public const string SubjectType = "subject_type";
            public const string TokenEndpointAuthenticationMethod = "token_endpoint_auth_method";
            public const string TokenEndpointAuthenticationSigningAlgorithm = "token_endpoint_auth_signing_alg";
            public const string DefaultMaxAge = "default_max_age";
            public const string RequireAuthenticationTime = "require_auth_time";
            public const string DefaultAcrValues = "default_acr_values";
            public const string InitiateLoginUris = "initiate_login_uri";
            public const string RequestUris = "request_uris";
            public const string IdentityTokenSignedResponseAlgorithm = "id_token_signed_response_alg";
            public const string IdentityTokenEncryptedResponseAlgorithm = "id_token_encrypted_response_alg";
            public const string IdentityTokenEncryptedResponseEncryption = "id_token_encrypted_response_enc";
            public const string UserinfoSignedResponseAlgorithm = "userinfo_signed_response_alg";
            public const string UserInfoEncryptedResponseAlgorithm = "userinfo_encrypted_response_alg";
            public const string UserinfoEncryptedResponseEncryption = "userinfo_encrypted_response_enc";
            public const string RequestObjectSigningAlgorithm = "request_object_signing_alg";
            public const string RequestObjectEncryptionAlgorithm = "request_object_encryption_alg";
            public const string RequestObjectEncryptionEncryption = "request_object_encryption_enc";
        }

        public static class TokenTypes
        {
            public const string AccessToken = "access_token";
            public const string IdentityToken = "id_token";
            public const string RefreshToken = "refresh_token";
        }

        public static class TokenTypeIdentifiers
        {
            public const string AccessToken = "urn:ietf:params:oauth:token-type:access_token";
            public const string IdentityToken = "urn:ietf:params:oauth:token-type:id_token";
            public const string RefreshToken = "urn:ietf:params:oauth:token-type:refresh_token";
            public const string Saml11 = "urn:ietf:params:oauth:token-type:saml1";
            public const string Saml2 = "urn:ietf:params:oauth:token-type:saml2";
        }

        public static class AuthenticationSchemes
        {
            public const string AuthorizationHeaderBearer = "Bearer";
            public const string FormPostBearer = "access_token";
            public const string QueryStringBearer = "access_token";

            public const string AuthorizationHeaderPop = "PoP";
            public const string FormPostPop = "pop_access_token";
            public const string QueryStringPop = "pop_access_token";
        }

        public static class GrantTypes
        {
            public const string Password = "password";
            public const string AuthorizationCode = "authorization_code";
            public const string ClientCredentials = "client_credentials";
            public const string RefreshToken = "refresh_token";
            public const string Implicit = "implicit";
            public const string Saml2Bearer = "urn:ietf:params:oauth:grant-type:saml2-bearer";
            public const string JwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
            public const string DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";
            public const string TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
        }

        public static class ClientAssertionTypes
        {
            public const string JwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
            public const string SamlBearer = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer";
        }

        public static class ResponseTypes
        {
            public const string Code = "code";
            public const string Token = "token";
            public const string IdToken = "id_token";
            public const string IdTokenToken = "id_token token";
            public const string CodeIdToken = "code id_token";
            public const string CodeToken = "code token";
            public const string CodeIdTokenToken = "code id_token token";
        }

        public static class ResponseModes
        {
            public const string FormPost = "form_post";
            public const string Query = "query";
            public const string Fragment = "fragment";
        }

        public static class DisplayModes
        {
            public const string Page = "page";
            public const string Popup = "popup";
            public const string Touch = "touch";
            public const string Wap = "wap";
        }

        public static class PromptModes
        {
            public const string None = "none";
            public const string Login = "login";
            public const string Consent = "consent";
            public const string SelectAccount = "select_account";
        }

        public static class CodeChallengeMethods
        {
            public const string Plain = "plain";
            public const string Sha256 = "S256";
        }

        public static class ProtectedResourceErrors
        {
            public const string InvalidToken = "invalid_token";
            public const string ExpiredToken = "expired_token";
            public const string InvalidRequest = "invalid_request";
            public const string InsufficientScope = "insufficient_scope";
        }

        public static class EndpointAuthenticationMethods
        {
            public const string PostBody = "client_secret_post";
            public const string BasicAuthentication = "client_secret_basic";
            public const string PrivateKeyJwt = "private_key_jwt";
            public const string TlsClientAuth = "tls_client_auth";
            public const string SelfSignedTlsClientAuth = "self_signed_tls_client_auth";
        }

        public static class AuthenticationMethods
        {
            public const string FacialRecognition = "face";
            public const string FingerprintBiometric = "fpt";
            public const string Geolocation = "geo";
            public const string ProofOfPossessionHardwareSecuredKey = "hwk";
            public const string IrisScanBiometric = "iris";
            public const string KnowledgeBasedAuthentication = "kba";
            public const string MultipleChannelAuthentication = "mca";
            public const string MultiFactorAuthentication = "mfa";
            public const string OneTimePassword = "otp";
            public const string PersonalIdentificationOrPattern = "pin";
            public const string Password = "pwd";
            public const string RiskBasedAuthentication = "rba";
            public const string RetinaScanBiometric = "retina";
            public const string SmartCard = "sc";
            public const string ConfirmationBySms = "sms";
            public const string ProofOfPossessionSoftwareSecuredKey = "swk";
            public const string ConfirmationByTelephone = "tel";
            public const string UserPresenceTest = "user";
            public const string VoiceBiometric = "vbm";
            public const string WindowsIntegratedAuthentication = "wia";
        }

        public static class Algorithms
        {
            public const string None = "none";

            public static class Symmetric
            {
                public const string HS256 = "HS256";
                public const string HS384 = "HS284";
                public const string HS512 = "HS512";
            }

            public static class Asymmetric
            {
                public const string RS256 = "RS256";
                public const string RS384 = "RS384";
                public const string RS512 = "RS512";

                public const string ES256 = "ES256";
                public const string ES384 = "ES384";
                public const string ES512 = "ES512";

                public const string PS256 = "PS256";
                public const string PS384 = "PS384";
                public const string PS512 = "PS512";

            }
        }

        public static class Discovery
        {
            public const string Issuer = "issuer";

            // endpoints
            public const string AuthorizationEndpoint = "authorization_endpoint";
            public const string DeviceAuthorizationEndpoint = "device_authorization_endpoint";
            public const string TokenEndpoint = "token_endpoint";
            public const string UserInfoEndpoint = "userinfo_endpoint";
            public const string IntrospectionEndpoint = "introspection_endpoint";
            public const string RevocationEndpoint = "revocation_endpoint";
            public const string DiscoveryEndpoint = ".well-known/openid-configuration";
            public const string JwksUri = "jwks_uri";
            public const string EndSessionEndpoint = "end_session_endpoint";
            public const string CheckSessionIframe = "check_session_iframe";
            public const string RegistrationEndpoint = "registration_endpoint";
            public const string MtlsEndpointAliases = "mtls_endpoint_aliases";

            // common capabilities
            public const string FrontChannelLogoutSupported = "frontchannel_logout_supported";
            public const string FrontChannelLogoutSessionSupported = "frontchannel_logout_session_supported";
            public const string BackChannelLogoutSupported = "backchannel_logout_supported";
            public const string BackChannelLogoutSessionSupported = "backchannel_logout_session_supported";
            public const string GrantTypesSupported = "grant_types_supported";
            public const string CodeChallengeMethodsSupported = "code_challenge_methods_supported";
            public const string ScopesSupported = "scopes_supported";
            public const string SubjectTypesSupported = "subject_types_supported";
            public const string ResponseModesSupported = "response_modes_supported";
            public const string ResponseTypesSupported = "response_types_supported";
            public const string ClaimsSupported = "claims_supported";
            public const string TokenEndpointAuthenticationMethodsSupported = "token_endpoint_auth_methods_supported";

            // more capabilities
            public const string ClaimsLocalesSupported = "claims_locales_supported";
            public const string ClaimsParameterSupported = "claims_parameter_supported";
            public const string ClaimTypesSupported = "claim_types_supported";
            public const string DisplayValuesSupported = "display_values_supported";
            public const string AcrValuesSupported = "acr_values_supported";
            public const string IdTokenEncryptionAlgorithmsSupported = "id_token_encryption_alg_values_supported";
            public const string IdTokenEncryptionEncValuesSupported = "id_token_encryption_enc_values_supported";
            public const string IdTokenSigningAlgorithmsSupported = "id_token_signing_alg_values_supported";
            public const string OpPolicyUri = "op_policy_uri";
            public const string OpTosUri = "op_tos_uri";
            public const string RequestObjectEncryptionAlgorithmsSupported = "request_object_encryption_alg_values_supported";
            public const string RequestObjectEncryptionEncValuesSupported = "request_object_encryption_enc_values_supported";
            public const string RequestObjectSigningAlgorithmsSupported = "request_object_signing_alg_values_supported";
            public const string RequestParameterSupported = "request_parameter_supported";
            public const string RequestUriParameterSupported = "request_uri_parameter_supported";
            public const string RequireRequestUriRegistration = "require_request_uri_registration";
            public const string ServiceDocumentation = "service_documentation";
            public const string TokenEndpointAuthSigningAlgorithmsSupported = "token_endpoint_auth_signing_alg_values_supported";
            public const string UILocalesSupported = "ui_locales_supported";
            public const string UserInfoEncryptionAlgorithmsSupported = "userinfo_encryption_alg_values_supported";
            public const string UserInfoEncryptionEncValuesSupported = "userinfo_encryption_enc_values_supported";
            public const string UserInfoSigningAlgorithmsSupported = "userinfo_signing_alg_values_supported";
            public const string TlsClientCertificateBoundAccessTokens = "tls_client_certificate_bound_access_tokens";
        }

        public static class Events
        {
            public const string BackChannelLogout = "http://schemas.openid.net/event/backchannel-logout";
        }

        public static class BackChannelLogoutRequest
        {
            public const string LogoutToken = "logout_token";
        }

        public static class StandardScopes
        {
            /// <summary>需要。 通知授权服务器客户端正在发出OpenID Connect请求。 如果<c> openid </ c>范围值不存在，则行为完全不确定。</summary>
            public const string OpenId = "openid";
            /// <summary>可选的。 此范围值请求访问最终用户的默认配置文件声明，这些声明是：<c> name </ c>，<c> family_name </ c>，<c> given_name </ c>，<c> middle_name </ c>，<c>昵称</ c>，<c>首选用户名</ c>，<c>配置文件</ c>，<c>图片</ c>，<c>网站</ c>，<c >性别</ c>，<c>生日</ c>，<c>区域信息</ c>，<c>语言环境</ c>和<c> updated_at </ c>。</summary>
            public const string Profile = "profile";
            /// <summary>可选的。 此范围值请求访问<c>电子邮件</ c>和<c> email_verified </ c>声明。</summary>
            public const string Email = "email";
            /// <summary>OPTIONAL. This scope value requests access to the <c>address</c> Claim.</summary>
            public const string Address = "address";
            /// <summary>OPTIONAL. This scope value requests access to the <c>phone_number</c> and <c>phone_number_verified</c> Claims.</summary>
            public const string Phone = "phone";
            /// <summary>此范围值一定不能与《 OpenID Connect隐式客户端实施指南1.0》一起使用。 请参阅《 OpenID Connect基本客户端实施指南1.0》（http://openid.net/specs/openid-connect-implicit-1_0.html#OpenID.Basic），了解其在OpenID Connect子集中的用法。</summary>
            public const string OfflineAccess = "offline_access";
        }
    }
```
### Principal
```
    /// <summary>
    /// 帮助程序类创建ClaimsPrincipal
    /// </summary>
    public static class Principal
    {
        /// <summary>
        /// 获取一个匿名的ClaimsPrincipal。
        /// </summary>
        public static ClaimsPrincipal Anonymous => new ClaimsPrincipal(Identity.Anonymous);

        /// <summary>
        /// 使用指定的身份验证类型和声明创建ClaimsPrincipal。
        /// </summary>
        /// <param name="authenticationType">Type of the authentication.</param>
        /// <param name="claims">The claims.</param>
        /// <returns></returns>
        public static ClaimsPrincipal Create(string authenticationType, params Claim[] claims)
        {
            return new ClaimsPrincipal(Identity.Create(authenticationType, claims));
        }

        /// <summary>
        /// 根据X509证书中的信息创建ClaimsPrincipal。
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="authenticationType">Type of the authentication.</param>
        /// <param name="includeAllClaims">if set to <c>true</c> [include all claims].</param>
        /// <returns></returns>
        public static ClaimsPrincipal CreateFromCertificate(X509Certificate2 certificate, string authenticationType = "X.509", bool includeAllClaims = false)
        {
            return new ClaimsPrincipal(Identity.CreateFromCertificate(certificate, authenticationType, includeAllClaims));
        }
    }
```
### StringExtensions
```
    /// <summary>
    /// 字符串扩展
    /// </summary>
    public static class StringExtensions
    {
        /// <summary>
        ///创建指定输入的SHA256哈希。
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>A hash</returns>
        public static string ToSha256(this string input)
        {
            if (input.IsMissing()) return string.Empty;

            using (var sha = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                var hash = sha.ComputeHash(bytes);

                return Convert.ToBase64String(hash);
            }
        }

        /// <summary>
        ///创建指定输入的SHA512哈希。
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>A hash</returns>
        public static string ToSha512(this string input)
        {
            if (input.IsMissing()) return string.Empty;

            using (var sha = SHA512.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                var hash = sha.ComputeHash(bytes);

                return Convert.ToBase64String(hash);
            }
        }
    }
```