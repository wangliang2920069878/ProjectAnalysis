|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AsyncLazy](#asynclazy)
* [DictionaryExtensions](#dictionaryextensions)
* [InternalStringExtensions](#internalstringextensions)
* [QueryHelpers](#queryhelpers)
* [TaskHelpers](#taskhelpers)
* [ValuesHelper](#valueshelper)
### AsyncLazy
```
  class AsyncLazy<T> : Lazy<Task<T>>
    {
        public AsyncLazy(Func<Task<T>> taskFactory) :
            base(() => GetTaskAsync(taskFactory).Unwrap())
        { }

        private static async Task<Task<T>> GetTaskAsync(Func<Task<T>> taskFactory)
        {
			if (TaskHelpers.CanFactoryStartNew)
			{
				// 在后台线程中运行任务工厂，并检索结果任务。
				return Task<Task<T>>.Factory.StartNew(taskFactory).Unwrap();
			}
			else
			{
				// 让任务工厂在自己的上下文中同步运行。
				await Task.Yield();

				return taskFactory();
			}
        }
        
        //TODO: at some point allow this
        //public AsyncLazy(Func<Task<T>> taskFactory, LazyThreadSafetyMode mode) :
        //    base(() => Task.Factory.StartNew(taskFactory).Unwrap(), mode)
        //{ }
    }
```
### DictionaryExtensions
```
///帮助类
        public static void AddOptional(this IDictionary<string, string> parameters, string key, string value)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));

            if (value.IsPresent())
            {
                if (parameters.ContainsKey(key))
                {
                    throw new InvalidOperationException($"Duplicate parameter: {key}");
                }
                else
                {
                    parameters.Add(key, value);
                }
            }
        }

        public static void AddRequired(this IDictionary<string, string> parameters, string key, string value, bool allowEmpty = false)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));

            if (value.IsPresent())
            {
                if (parameters.ContainsKey(key))
                {
                    throw new InvalidOperationException($"Duplicate parameter: {key}");
                }
                else
                {
                    parameters.Add(key, value);
                }
            }
            else
            {
                if (allowEmpty)
                {
                    parameters.Add(key, "");
                }
                else
                {
                    throw new ArgumentException("Parameter is required", key);
                }
            }
        }
```
### InternalStringExtensions
```
///帮助类
    internal static class InternalStringExtensions
    {
        [DebuggerStepThrough]
        public static bool IsMissing(this string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        [DebuggerStepThrough]
        public static bool IsPresent(this string value)
        {
            return !(value.IsMissing());
        }

        [DebuggerStepThrough]
        public static string EnsureTrailingSlash(this string url)
        {
            if (!url.EndsWith("/"))
            {
                return url + "/";
            }

            return url;
        }

        [DebuggerStepThrough]
        public static string RemoveTrailingSlash(this string url)
        {
            if (url != null && url.EndsWith("/"))
            {
                url = url.Substring(0, url.Length - 1);
            }

            return url;
        }
    }
```
### QueryHelpers
```
    internal static class QueryHelpers
    {
        /// <summary>
        /// 将给定的查询键和值附加到URI。
        /// </summary>
        /// <param name="uri">The base URI.</param>
        /// <param name="name">The name of the query key.</param>
        /// <param name="value">The query value.</param>
        /// <returns>The combined result.</returns>
        public static string AddQueryString(string uri, string name, string value)
        {
            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            return AddQueryString(
                uri, new[] { new KeyValuePair<string, string>(name, value) });
        }

        /// <summary>
        /// 将给定的查询键和值附加到uri。
        /// </summary>
        /// <param name="uri">The base uri.</param>
        /// <param name="queryString">A collection of name value query pairs to append.</param>
        /// <returns>The combined result.</returns>
        public static string AddQueryString(string uri, IDictionary<string, string> queryString)
        {
            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            if (queryString == null)
            {
                throw new ArgumentNullException(nameof(queryString));
            }

            return AddQueryString(uri, (IEnumerable<KeyValuePair<string, string>>)queryString);
        }

        private static string AddQueryString(
            string uri,
            IEnumerable<KeyValuePair<string, string>> queryString)
        {
            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            if (queryString == null)
            {
                throw new ArgumentNullException(nameof(queryString));
            }

            var anchorIndex = uri.IndexOf('#');
            var uriToBeAppended = uri;
            var anchorText = "";
            // If there is an anchor, then the query string must be inserted before its first occurance.
            if (anchorIndex != -1)
            {
                anchorText = uri.Substring(anchorIndex);
                uriToBeAppended = uri.Substring(0, anchorIndex);
            }

            var queryIndex = uriToBeAppended.IndexOf('?');
            var hasQuery = queryIndex != -1;

            var sb = new StringBuilder();
            sb.Append(uriToBeAppended);
            foreach (var parameter in queryString)
            {
                if (parameter.Value == null) continue;

                sb.Append(hasQuery ? '&' : '?');
                sb.Append(UrlEncoder.Default.Encode(parameter.Key));
                sb.Append('=');
                sb.Append(UrlEncoder.Default.Encode(parameter.Value));
                hasQuery = true;
            }

            sb.Append(anchorText);
            return sb.ToString();
        }
    }
```
### TaskHelpers
```
    /// <summary>
    ///处理任务帮手。
    /// </summary>
    public static class TaskHelpers
    {
        /// <summary>
        /// 获取或设置此库的内部任务是否可以调用ConfigureAwait（false）。异步是否捕获上下文
        /// </summary>
        public static bool CanConfigureAwaitFalse { get; set; } = true;

		/// <summary>
		/// 获取或设置此库的内部任务是否可以调用<see cref =“ TaskFactory.StartNew(System.Action)"/>.
		/// </summary>
		public static bool CanFactoryStartNew { get; set; } = true;

		internal static ConfiguredTaskAwaitable ConfigureAwait(this Task task)
            => task.ConfigureAwait(!CanConfigureAwaitFalse);

        internal static ConfiguredTaskAwaitable<TResult> ConfigureAwait<TResult>(this Task<TResult> task)
            => task.ConfigureAwait(!CanConfigureAwaitFalse);
    }
```
### ValuesHelper
```
    /// <summary>
    /// 帮助者处理键/值对
    /// </summary>
    public static class ValuesHelper
    {
        /// <summary>
        ///将对象转换为字典。
        /// </summary>
        /// <param name="values">The values.</param>
        /// <returns></returns>
        public static Dictionary<string, string> ObjectToDictionary(object values)
        {
            if (values == null)
            {
                return null;
            }

            if (values is Dictionary<string, string> dictionary) return dictionary;

            dictionary = new Dictionary<string, string>();

            foreach (var prop in values.GetType().GetRuntimeProperties())
            {
                var value = prop.GetValue(values) as string;
                if (value.IsPresent())
                {
                    dictionary.Add(prop.Name, value);
                }
            }

            return dictionary;
        }

        /// <summary>
        /// Merges two dictionaries
        /// </summary>
        /// <param name="explicitValues">The explicit values.</param>
        /// <param name="additionalValues">The additional values.</param>
        /// <returns></returns>
        public static Dictionary<string, string> Merge(Dictionary<string, string> explicitValues, Dictionary<string, string> additionalValues = null)
        {
            var merged = explicitValues;

            if (additionalValues != null)
            {
                merged =
                    explicitValues.Concat(additionalValues.Where(add => !explicitValues.ContainsKey(add.Key)))
                                         .ToDictionary(final => final.Key, final => final.Value);
            }

            return merged;
        }
    }
```