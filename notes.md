
## webapp security
[跨站请求伪造(英语：Cross-site request forgery)](https://zh.wikipedia.org/wiki/%E8%B7%A8%E7%AB%99%E8%AF%B7%E6%B1%82%E4%BC%AA%E9%80%A0)
这利用了web中用户身份验证的一个漏洞：**简单的身份验证只能保证请求发自某个用户的浏览器，却不能保证请求本身是用户自愿发出的。**
原理就是通过浏览器不加检查的直接访问一些链接，比如一个\<img src=''\>, 浏览器就会访问这个链接，但是用户并没有操作，而是浏览器操作的；如果某个银行站点你刚刚登陆过，并且cookie什么的都没过期，也取得了银行站点信任，而攻击者又知道银行转账的具体url，那么你就会被自动转账了。
防御措施：
 1. 检查Referer字段
   - 字段用以标明请求来源于哪个地址。在处理敏感数据请求时，通常来说，Referer字段应和请求的地址位于同一域名下,但是还是防止不了攻击者篡改Referer
 2. 添加校验token
   - 就是服务器给form表单附加一个数据做校验，这样攻击者就不知道这个随机校验码了；只有用户主动填写才可能拿到校验码；

[Flask-WTF](http://packages.python.org/Flask-WTF) 中的 WTF\_CSRF\_ENABLED 默认是设置为真的，用来防止CSRF攻击， SECRET\_KEY 就是用来产生 cryptographic token 的；
用户密码验证采用的是[OpenID](http://openid.net/),可以通过 Flask-WTF 里的 validator 得到；

模板中的 form.hidden_tag() 就是用于验证防止CSRF攻击的token字段，WTF会帮我们处理和验证此字段， 并且这里的表单不是HTML硬编码，而是form 类，通过传递参数给模板

## orm & database migration
one-to-many lazy

## user authentication
