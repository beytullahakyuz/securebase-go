## TR

SecureBase kütüphanesi standart base64 algoritmasına ek olarak gizli anahtar seçeneği sunmaktadır. Böylelikle kütüphaneyi kullanan projelere özgü base64 işlemi gerçekleşir. Her projenin gizli anahtarı farklı olacağından oluşan base64 çıktısıda gizli anahtara bağlı olarak değişir.

Detaylı bilgi için aşağıdaki kaynağı inceleyiniz.

[SecureBase Wiki](https://beytullahakyuz.gitbook.io/securebase)

## Kullanım/Örnek

```
go get github.com/beytullahakyuz/securebase-go
```

```go
import (
	SecureBase "github.com/beytullahakyuz/securebase-go"
)

var encoding SecureBase.SBEncoding
//encoding = SecureBase.UNICODE
encoding = SecureBase.UTF8

sb := SecureBase.NewSecureBase(encoding)
sb.SetSecretKey(secretkey)

//Encoding
encoded, err := sb.Encode("data")
if err != nil {
	return err.Error()
}

//Decoding
decoded, err := sb.Decode(encoded)
if err != nil {
	return err.Error()
}
```

## Ekran Görüntüleri

Kodlama (Farklı gizli anahtarlarla)

![Kodlama](https://github.com/beytullahakyuz/assets/blob/main/securebase-go/scr1.png)
![Kodlama](https://github.com/beytullahakyuz/assets/blob/main/securebase-go/scr2.png)

Kod çözme

![Kod çözme](https://github.com/beytullahakyuz/assets/blob/main/securebase-go/scr2.png)
![Kod çözme](https://github.com/beytullahakyuz/assets/blob/main/securebase-go/scr4.png)


## EN

The SecureBase library offers a secret key option in addition to the standard base64 algorithm. Since the secret key will be different in each project, the base64 output will also vary depending on the secret key.

For detailed information, please review the source below.

[SecureBase Wiki](https://beytullahakyuz.gitbook.io/securebase)

## Using/Example

```
go get github.com/beytullahakyuz/securebase-go
```

```go
import (
	SecureBase "github.com/beytullahakyuz/securebase-go"
)

var encoding SecureBase.SBEncoding
//encoding = SecureBase.UNICODE
encoding = SecureBase.UTF8

sb := SecureBase.NewSecureBase(encoding)
sb.SetSecretKey(secretkey)

//Encoding
encoded, err := sb.Encode("data")
if err != nil {
	return err.Error()
}

//Decoding
decoded, err := sb.Decode(encoded)
if err != nil {
	return err.Error()
}
```

## Screenshots

Encoding (Different secret keys)

![Encoding](https://github.com/beytullahakyuz/assets/blob/main/securebase-go/scr1.png)
![Encoding](https://github.com/beytullahakyuz/assets/blob/main/securebase-go/scr2.png)

Decoding

![Decoding](https://github.com/beytullahakyuz/assets/blob/main/securebase-go/scr2.png)
![Decoding](https://github.com/beytullahakyuz/assets/blob/main/securebase-go/scr4.png)
