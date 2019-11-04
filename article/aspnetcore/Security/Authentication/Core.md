|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AuthenticationSchemeOptions](#authenticationschemeoptions)
* [标题](#标题)
* [文本](#文本)






### AuthenticationSchemeOptions
    解释：包含由AuthenticationHandler所使用的选项
虚方法
```
public virtual void Validate() { }

解释：检查选项是否有效。 如果情况不好，应该抛出异常。
```
属性
```
 public string ClaimsIssuer { get; set; }
 解释：获取或设置应用于创建的任何声明的颁发者
```
```
public object Events { get; set; }

解释：用于事件的实例
```
```
public Type EventsType { get; set; }

解释：如果设置，将用作获取事件实例
```
```
public string ForwardDefault { get; set; }

解释：如果设置，则指定身份验证处理程序应将所有身份验证操作转发到的默认方案
 默认。 默认转发逻辑将检查最具体的ForwardAuthenticate / Challenge / Forbid / SignIn / SignOut
 首先进行设置，然后检查ForwardDefaultSelector，再检查ForwardDefault。 第一个非空结果
 将用作转发到的目标方案。
```
```
public string ForwardAuthenticate { get; set; }

解释：如果设置，则指定此方案应将AuthenticateAsync调用转发到的目标方案。
例如Context.AuthenticateAsync（“ ThisScheme”）=> Context.AuthenticateAsync（“ ForwardAuthenticateValue”）;
将目标设置为当前方案以禁用转发并允许正常处理。
```
```
public string ForwardChallenge { get; set; }

解释：如果设置，则指定该方案应将ChallengeAsync调用转发到的目标方案。
例如Context.ChallengeAsync（“ ThisScheme”）=> Context.ChallengeAsync（“ ForwardChallengeValue”将目标设置为当前方案以禁用转发并允许正常处理。
```
```
public string ForwardForbid { get; set; }

解释：如果设置，则指定该方案应将ForbidAsync调用转发到的目标方案。
例如Context.ForbidAsync（“ ThisScheme”）=> Context.ForbidAsync（“ ForwardForbidValue”）;
将目标设置为当前方案以禁用转发并允许正常处理。
```

```
public string ForwardSignIn { get; set; }

解释：如果设置，则指定此方案应将SignInAsync调用转发到的目标方案。
  例如Context.SignInAsync（“ ThisScheme”）=> Context.SignInAsync（“ ForwardSignInValue”）;
将目标设置为当前方案以禁用转发并允许正常处理。
```
```
public string ForwardSignOut { get; set; }

解释：如果设置，则指定此方案应将SignOutAsync调用转发到的目标方案。
  例如Context.SignOutAsync（“ ThisScheme”）=> Context.SignOutAsync（“ ForwardSignOutValue”）;
将目标设置为当前方案以禁用转发并允许正常处理。
```
```
public Func<HttpContext, string> ForwardDefaultSelector { get; set; }

解释：用于为当前请求选择默认方案，身份验证处理程序应将所有身份验证操作转发给该默认方案
默认。 默认转发逻辑将检查最具体的ForwardAuthenticate / Challenge / Forbid / SignIn / SignOut
设置，然后检查ForwardDefaultSelector，再检查ForwardDefault。 第一个非空结果
将用作转发的目标方案。
```