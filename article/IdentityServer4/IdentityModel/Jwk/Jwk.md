|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [JsonWebAlgorithmsKeyTypes](#jsonwebalgorithmskeytypes)
* [JsonWebKey](#jsonwebkey)
* [JsonWebKeyParameterNames](#jsonwebkeyparameternames)
* [JsonWebKeySet](#jsonwebkeyset)
* [JsonWebKeyExtensions](#jsonwebkeyextensions)
### JsonWebAlgorithmsKeyTypes
```
    /// <summary>
    /// Constants for JsonWebAlgorithms  "kty" Key Type (sec 6.1)
    /// http://tools.ietf.org/html/rfc7518#section-6.1
    /// </summary>
    public static class JsonWebAlgorithmsKeyTypes
    {
#pragma warning disable 1591
        public const string EllipticCurve = "EC";
        public const string RSA = "RSA";
        public const string Octet = "oct";
#pragma warning restore 1591
    }
```

### JsonWebKey
```
    /// <summary>
    /// 代表http://tools.ietf.org/html/rfc7517中定义的Json Web Key。
    /// </summary>
    [JsonObject]
    public class JsonWebKey
    {
        // 保持私有以隐藏使用列表。
         //公共成员返回一个IList。
        private IList<string> _certificateClauses = new List<string>();
        private IList<string> _keyops = new List<string>();

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKey"/>.
        /// </summary>
        public JsonWebKey()
        { }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKey"/> from a json string.
        /// </summary>
        /// <param name="json">一个字符串，其中包含JSON格式的JSON Web Key参数。</param>
        public JsonWebKey(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) throw new ArgumentNullException(nameof(json));

            var key = JsonConvert.DeserializeObject<JsonWebKey>(json);
            Copy(key);
        }

        private void Copy(JsonWebKey key)
        {
            this.Alg = key.Alg;
            this.Crv = key.Crv;
            this.D = key.D;
            this.DP = key.DP;
            this.DQ = key.DQ;
            this.E = key.E;
            this.K = key.K;
            if (key.KeyOps != null)
                _keyops = new List<string>(key.KeyOps);
            this.Kid = key.Kid;
            this.Kty = key.Kty;
            this.N = key.N;
            this.Oth = key.Oth;
            this.P = key.P;
            this.Q = key.Q;
            this.QI = key.QI;
            this.Use = key.Use;
            if (key.X5c != null)
                _certificateClauses = new List<string>(key.X5c);
            this.X5t = key.X5t;
            this.X5tS256 = key.X5tS256;
            this.X5u = key.X5u;
            this.X = key.X;
            this.Y = key.Y;
        }

        /// <summary>
        /// 获取或设置'alg'（KeyType）。
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Alg, Required = Required.Default)]
        public string Alg { get; set; }

        /// <summary>
        /// 获取或设置“ crv”（ECC-曲线）。
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Crv, Required = Required.Default)]
        public string Crv { get; set; }

        /// <summary>
        /// 获取或设置'd'（ECC-私钥或RSA-私有指数）。
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.D, Required = Required.Default)]
        public string D { get; set; }

        /// <summary>
        /// 获取或设置“ dp”（RSA-第一因素CRT指数）。
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DP, Required = Required.Default)]
        public string DP { get; set; }

        /// <summary>
        /// 获取或设置“ dq”（RSA-第二因素CRT指数）。
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DQ, Required = Required.Default)]
        public string DQ { get; set; }

        /// <summary>
        /// 获取或设置“ e”（RSA-指数）。
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.E, Required = Required.Default)]
        public string E { get; set; }

        /// <summary>
        /// 获取或设置“ k”（对称-键值）。
        /// </summary>
        /// Base64urlEncoding
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.K, Required = Required.Default)]
        public string K { get; set; }

        /// <summary>
        /// 获取或设置“ key_ops”（键操作）。
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.KeyOps, Required = Required.Default)]
        public IList<string> KeyOps
        {
            get
            {
                return _keyops;
            }
            set
            {
                if (value == null) throw new ArgumentNullException("KeyOps");

                foreach (string keyOp in value)
                    _keyops.Add(keyOp);
            }
        }

        /// <summary>
        /// 获取或设置“kid”（密钥ID）。
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kid, Required = Required.Default)]
        public string Kid { get; set; }

        /// <summary>
        /// 获取或设置“ kty”（密钥类型）。
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kty, Required = Required.Default)]
        public string Kty { get; set; }

        /// <summary>
        /// 获取或设置“ n”（RSA-模数）。
        /// </summary>
        /// <remarks> value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.N, Required = Required.Default)]
        public string N { get; set; }

        /// <summary>
        ///获取或设置“ oth”（RSA-其他素数信息）。
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Oth, Required = Required.Default)]
        public IList<string> Oth { get; set; }

        /// <summary>
        ///获取或设置“ p”（RSA-第一个素数）。
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.P, Required = Required.Default)]
        public string P { get; set; }

        /// <summary>
        /// Gets or sets the 'q' (RSA - Second  Prime Factor)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Q, Required = Required.Default)]
        public string Q { get; set; }

        /// <summary>
        /// Gets or sets the 'qi' (RSA - First CRT Coefficient)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.QI, Required = Required.Default)]
        public string QI { get; set; }

        /// <summary>
        /// Gets or sets the 'use' (Public Key Use)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Use, Required = Required.Default)]
        public string Use { get; set; }

        /// <summary>
        /// Gets or sets the 'x' (ECC - X Coordinate)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X, Required = Required.Default)]
        public string X { get; set; }

        /// <summary>
        /// Gets the 'x5c' collection (X.509 Certificate Chain)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5c, Required = Required.Default)]
        public IList<string> X5c
        {
            get
            {
                return _certificateClauses;
            }
            set
            {
                //if (value == null)
                //    throw LogHelper.LogException<ArgumentNullException>(LogMessages.IDX10001, "X5c");

                foreach (string clause in value)
                    _certificateClauses.Add(clause);
            }
        }

        /// <summary>
        ///获取或设置“ x5t”（X.509证书SHA-1指纹）。
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5t, Required = Required.Default)]
        public string X5t { get; set; }

        /// <summary>
        /// Gets or sets the 'x5t#S256' (X.509 Certificate SHA-1 thumbprint)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5tS256, Required = Required.Default)]
        public string X5tS256 { get; set; }

        /// <summary>
        /// Gets or sets the 'x5u' (X.509 URL)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5u, Required = Required.Default)]
        public string X5u { get; set; }

        /// <summary>
        ///获取或设置“ y”（ECC-Y坐标）。
        /// </summary>
        /// <remarks> value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Y, Required = Required.Default)]
        public string Y { get; set; }

        public int KeySize
        {
            get
            {
                if (Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return Base64Url.Decode(N).Length * 8;
                else if (Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                    return Base64Url.Decode(X).Length * 8;
                else if (Kty == JsonWebAlgorithmsKeyTypes.Octet)
                    return Base64Url.Decode(K).Length * 8;
                else
                    return 0;
            }
        }

        public bool HasPrivateKey
        {
            get
            {
                if (Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return D != null && DP != null && DQ != null && P != null && Q != null && QI != null;
                else if (Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                    return D != null;
                else
                    return false;
            }
        }
    }
```
### JsonWebKeyParameterNames
```
   /// <summary>
    ///Json Web键值的名称
    /// </summary>
    public static class JsonWebKeyParameterNames
    {
#pragma warning disable 1591
        public const string Alg = "alg";
        public const string Crv = "crv";
        public const string D = "d";
        public const string DP = "dp";
        public const string DQ = "dq";
        public const string E = "e";
        public const string K = "k";
        public const string KeyOps = "key_ops";
        public const string Keys = "keys";
        public const string Kid = "kid";
        public const string Kty = "kty";
        public const string N = "n";
        public const string Oth = "oth";
        public const string P = "p";
        public const string Q = "q";
        public const string R = "r";
        public const string T = "t";
        public const string QI = "qi";
        public const string Use = "use";
        public const string X5c = "x5c";
        public const string X5t = "x5t";
        public const string X5tS256 = "x5t#S256";
        public const string X5u = "x5u";
        public const string X = "x";
        public const string Y = "y";
#pragma warning restore 1591
    }
```
### JsonWebKeySet
```
    /// <summary>
    /// 包含<see cref =“ JsonWebKey” />的集合，可以从json字符串填充该集合。
    /// </summary>
    public class JsonWebKeySet
    {
        private List<JsonWebKey> _keys = new List<JsonWebKey>();

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/>.
        /// </summary>
        public JsonWebKeySet()
        { }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing values.</param>
        /// <exception cref="ArgumentNullException">if 'json' is null or whitespace.</exception>
        public JsonWebKeySet(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) throw new ArgumentNullException("json");

            var jwebKeys = JsonConvert.DeserializeObject<JsonWebKeySet>(json);
            _keys = jwebKeys._keys;
        }

        /// <summary>
        /// 获取<see cref =“ IList {JsonWebKey}” />。
        /// </summary>       
        public IList<JsonWebKey> Keys
        {
            get
            {
                return _keys;
            }
        }
    }
```
### JsonWebKeyExtensions
```
    /// <summary>
    /// JsonWebKey的扩展
    /// </summary>
    public static class JsonWebKeyExtensions
    {
        /// <summary>
        /// 将JSON Web密钥转换为URL安全字符串。
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        public static string ToJwkString(this JsonWebKey key)
        {
            var json = JsonConvert.SerializeObject(key);            
            return Base64Url.Encode(Encoding.UTF8.GetBytes(json));
        }
    }
```