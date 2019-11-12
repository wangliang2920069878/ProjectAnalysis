|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [X509](#x509)
* [X509CertificatesFinder](#x509certificatesfinder)
* [X509CertificatesLocation](#x509certificateslocation)
* [X509CertificatesName](#x509certificatesname)
### X509
```
    public static class X509
    {
        public static X509CertificatesLocation CurrentUser => new X509CertificatesLocation(StoreLocation.CurrentUser);
        public static X509CertificatesLocation LocalMachine => new X509CertificatesLocation(StoreLocation.LocalMachine);
    }
```
### X509CertificatesFinder
```
//搜索X509Certificate2证书
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class X509CertificatesFinder
    {
        readonly StoreLocation _location;
        readonly StoreName _name;
        readonly X509FindType _findType;

        public X509CertificatesFinder(StoreLocation location, StoreName name, X509FindType findType)
        {
            _location = location;
            _name = name;
            _findType = findType;
        }

        public IEnumerable<X509Certificate2> Find(object findValue, bool validOnly = true)
        {
#if NET452
            var store = new X509Store(_name, _location);
            store.Open(OpenFlags.ReadOnly);

            try
            {
                var certColl = store.Certificates.Find(_findType, findValue, validOnly);
                store.Close();
                return certColl.Cast<X509Certificate2>();
            }
            finally
            {
                store.Close();
            }
#else
            using (var store = new X509Store(_name, _location))
            {
                store.Open(OpenFlags.ReadOnly);

                var certColl = store.Certificates.Find(_findType, findValue, validOnly);
                return certColl.Cast<X509Certificate2>();
            }
#endif
        }
    }
```
### X509CertificatesLocation
```
//证书存储区
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class X509CertificatesLocation
    {
        readonly StoreLocation _location;

        public X509CertificatesLocation(StoreLocation location)
        {
            _location = location;
        }

        public X509CertificatesName My => new X509CertificatesName(_location, StoreName.My);
        public X509CertificatesName AddressBook => new X509CertificatesName(_location, StoreName.AddressBook);
        public X509CertificatesName TrustedPeople => new X509CertificatesName(_location, StoreName.TrustedPeople);
        public X509CertificatesName TrustedPublisher => new X509CertificatesName(_location, StoreName.TrustedPublisher);
        public X509CertificatesName CertificateAuthority => new X509CertificatesName(_location, StoreName.CertificateAuthority);
    }
```
### X509CertificatesName
```
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class X509CertificatesName
    {
        readonly StoreLocation _location;
        readonly StoreName _name;

        public X509CertificatesName(StoreLocation location, StoreName name)
        {
            _location = location;
            _name = name;
        }

        public X509CertificatesFinder Thumbprint => new X509CertificatesFinder(_location, _name, X509FindType.FindByThumbprint);
        public X509CertificatesFinder SubjectDistinguishedName => new X509CertificatesFinder(_location, _name, X509FindType.FindBySubjectDistinguishedName);
        public X509CertificatesFinder SerialNumber => new X509CertificatesFinder(_location, _name, X509FindType.FindBySerialNumber);
        public X509CertificatesFinder IssuerName => new X509CertificatesFinder(_location, _name, X509FindType.FindByIssuerName);
    }
```