[TOC]

# Flask
## Flask 上下文全局变量
|变量名       |上下文      |说明 |
|------------|:-----------|:---------------|
| curret_app |application|当前激活程序的程序实例|
| g          |application|处理请求时用作临时存储的对象，每次请求都会重设这个变量|
| request    |request    |请求对象，封装了客户端发出的HTTP请求中的内容|
| session    |request之间 |用户会话，用于存储请求之间需要“记住”的值的词典|
程序上下文需要激活之后才能使用
```python
>>> from hello import app
>>> from flask import current_app
>>> current_app.name
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/local/lib/python2.7/dist-packages/werkzeug/local.py", line 343, in __getattr__
    return getattr(self._get_current_object(), name)
  File "/usr/local/lib/python2.7/dist-packages/werkzeug/local.py", line 302, in _get_current_object
    return self.__local()
  File "/usr/local/lib/python2.7/dist-packages/flask/globals.py", line 51, in _find_app
    raise RuntimeError(_app_ctx_err_msg)
RuntimeError: Working outside of application context.

This typically means that you attempted to use functionality that needed
to interface with the current application object in a way.  To solve
this set up an application context with app.app_context().  See the
documentation for more information.
>>> app_ctx = app.app_context()
>>> app_ctx.push()
>>> current_app.name
'hello'
>>> app_ctx.pop()

```
## 请求调度
这里的@app.route() 实际上等价于 app.add\_url\_rule() 用来生成映射
```python
>>> from hello import app
>>> app.url_map
Map([<Rule '/' (HEAD, OPTIONS, GET) -> index>,
 <Rule '/static/<filename>' (HEAD, OPTIONS, GET) -> static>,
 <Rule '/user/<name>' (HEAD, OPTIONS, GET) -> user>])
>>> 
```
url_for() 函数的第一个且唯一必须指定的参数是端点名，即路由的内部名字。 默认情
况下，路由的端点是相应视图函数的名字。

## 请求钩子
实际上就是装饰器模式，处理一些通用的功能如认证和日志，包装等
  - befor\_first\_request：注册一个函数，在处理第一个请求之前运行。
  - before\_request：注册一个函数，在每次请求之前运行。
  - after\_request：注册一个函数，如果没有未处理的异常抛出，在每次请求之后运行。
  - teardown\_request：注册一个函数，即使有未处理的异常抛出，也在每次请求之后运行

请求钩子函数和视图函数之间共享数据一般使用上下文全局变量 g

## 响应
可以直接 return body, statuscode, header_dict 三元组，
可以使用make\_response() 函数，构造Response对象
```python
from flask import make_response
@app.route('/')
def index():
  response = make_response('<h1>This document carries a cookie!</h1>')
  response.set_cookie('answer', '42')
return response
```
用户输入名字后提交表单，然后点击浏览器的刷新按钮，会看到一个莫名其妙的警告，要求在再次提交表单之前进行确认。之所以出现这
种情况，是因为刷新页面时浏览器会重新发送之前已经发送过的最后一个请求。如果这个请求是一个包含表单数据的 POST 请求，刷新页面后会再次提交表单。大多数情况下，这并
不是理想的处理方式。

重定向函数redirect，其实就是302状态码的response；重定
向是一种特殊的响应， 响应内容是 URL，而不是包含 HTML 代码的字符串。浏览器收到
这种响应时， 会向重定向的 URL 发起 GET 请求，显示页面的内容。这个页面的加载可能
要多花几微秒， 因为要先把第二个请求发给服务器。

最后一个而是abort(404)函数，但是此函数不会把控制权交给调用它的函数，而是跑出异常把控制权交给web服务器；

在模板中使用循环是因为在之前的请求循环中每次调用 flash() 函数时都会生成一个消息，
所以可能有多个消息在排队等待显示。 get_flashed_messages() 函数获取的消息在下次调
用时不会再次返回，因此 Flash 消息只显示一次，然后就消失了。


## 扩展
### 命令行扩展flask-script
flask 的开发 Web 服务器支持很多启动设置选项，但只能在脚本中作为参数传给 app.run()
函数。这种方式并不十分方便，传递设置选项的理想方式是使用命令行参数。

Flask-Script 是一个 Flask 扩展，为 Flask 程序添加了一个命令行解析器。 Flask-Script 自带
了一组常用选项，而且还支持自定义命令。
```python
from flask.ext.script import Manager
manager = Manager(app)
# ...
if __name__ == '__main__':
manager.run()
```

## 模板中的
Jinja2模板可以使用继承，包含，宏等进行模板复用
flask-bootstrap 集成了Twitter-bootstrap；可以很方便的在后台服务器引用bootstrap的css和js；
Flask 提供了 url\_for() 辅助函数，它可以使用程序 URL 映射中保存
的信息生成 URL。
url\_for() 函数最简单的用法是以视图函数名（或者 app.add\_url\_route() 定义路由时使用的端点名）作为参数， 返回对应的 URL。例如，在当前版本的 hello.py 程序中调用 url\_for('index') 得到的结果是 /。调用 url\_for('index', \_external=True) 返回的则是绝对地址，在这个示例中是 http://localhost:5000/。
**生成连接程序内不同路由的链接时，使用相对地址就足够了。如果要生成在浏览器之外使用的链接， 则必须使用绝对地址**，例如在电子邮件中发送的链接
flask-moment 是把moment.js前端框架集成到jinja2的flask扩展



### flask-wtf (webapp security)
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

### wtf 表单验证
```python
class NameForm(Form):
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('Submit')

@app.route('/', methods=['GET', 'POST'])
def index():
    name = None
    form = NameForm()
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
    return render_template('index.html', form=form, name=name)
```
提交表单后，如果数据能被所有验证函数接受， 那么 validate_on_submit() 方法的返回值为 True，否则返回 False。这个函数的返回值决定是重新渲染表单还是处理表单提交的数据。

用户第一次访问程序时， 服务器会收到一个没有表单数据的 GET 请求，所以 validate\_on\_submit() 将返回 False。 if 语句的内容将被跳过，通过渲染模板处理请求，并传入表单对
象和值为 None 的 name 变量作为参数。用户会看到浏览器中显示了一个表单。用户提交表单后， 服务器收到一个包含数据的 POST 请求。 validate\_on\_submit() 会调用
name 字段上附属的 Required() 验证函数。如果名字不为空，就能通过验证， validate\_on\_submit() 返回 True。现在，用户输入的名字可通过字段的 data 属性获取。在 if 语句中，
把名字赋值给局部变量 name，然后再把 data 属性设为空字符串，从而清空表单字段。最后一行调用 render\_template() 函数渲染模板，但这一次参数 name 的值为表单中输入的名
字，因此会显示一个针对该用户的欢迎消息。

### wtf 表单渲染
使用flask-wtf 制造的表单类，在嵌入到jinja2模板时候，需要和bootstrap配合，从而能够被渲染，因此需要给form的字段设置id，如下方法：
```
<form method="POST">
{{ form.hidden_tag() }}
{{ form.name.label }} {{ form.name(id='my-text-field') }}
{{ form.submit() }}
</form>
```
即便能指定 HTML 属性，但按照这种方式渲染表单的工作量还是很大，所以在条件允许的
情况下最好能使用 Bootstrap 中的表单样式。 Flask-Bootstrap 提供了一个非常高端的辅助函
数，可以使用 Bootstrap 中预先定义好的表单样式渲染整个 Flask-WTF 表单，而这些操作
只需一次调用即可完成。使用 Flask-Bootstrap，上述表单可使用下面的方式渲染：
```
{% import "bootstrap/wtf.html" as wtf %}
{{ wtf.quick_form(form) }}
```

## flask-sqlalchemy orm & database migration
模型以及模型之间的关系，重点是关系的定义方式；以下是user 和 role的一对多模型
user : role = 1 : n; 在 1 : n 模型中， 一般表的表现形式是 1 中 使用一个 n 方的主键作为外键；
```python
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
```

one-to-many lazy
many-to-many( self-many-to-many)
### orm 操作
创建和删除，如果没有遇到commit，那么所有的模型对象都是内存中的Python对象，还没有写入数据库，因此不知道role的id
```python
>>> from hello import db
>>> db.create_all()
>>> db.create_all()
>>> db.drop_all()
>>> db.create_all()
>>> from hello import Role, User
>>> admin_role = Role(name='Admin')
>>> mod_role = Role(name='Moderator')
>>> user_role = Role(name='User')
>>> user_john = User(username='john', role=admin_role)
>>> user_susan = User(username='susan', role=user_role)
>>> user_david = User(username='david', role=user_role)
>>> print(admin_role.id)
None
>>> print(mod_role.id)
None
>>> print(user_role.id)
None
```
使用db.session.add() 和 db.session.commit() 提交数据库实务，也可以使用db.session.rollback()回滚
```python
>>> db.session.add([admin_role, mod_role, user_role, user_john, user_susan, user_david])
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/local/lib/python2.7/dist-packages/sqlalchemy/orm/scoping.py", line 157, in do
    return getattr(self.registry(), name)(*args, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/sqlalchemy/orm/session.py", line 1675, in add
    raise exc.UnmappedInstanceError(instance)
sqlalchemy.orm.exc.UnmappedInstanceError: Class '__builtin__.list' is not mapped
>>> db.session.add_all([admin_role, mod_role, user_role, user_john, user_susan, user_david])
>>> db.session.commit()
>>> print(admin_role.id)
1
>>> print(mod_role.id)
2
>>> print(user_role.id)
3
>>> admin_role.name='Administrator'
>>> db.session.add(admin_role)
>>> db.session.commit()
>>> db.session.delete(mod_role)
>>> db.session.commit()
```
查询
```python
>>> Role.query.all()
[<Role u'Administrator'>, <Role u'User'>]
>>> User.query.all()
[<User u'john'>, <User u'susan'>, <User u'david'>]
>>> User.query.filter_by(role=user_role).all()
[<User u'susan'>, <User u'david'>]
>>> str(User.query.filter_by(role=user_role))
'SELECT users.id AS users_id, users.username AS users_username, users.role_id AS users_role_id \nFROM users \nWHERE ? = users.role_id'
>>> user_role = Role.query.filter_by(name='User').first()
>>> users = user_role.users
>>> users
<sqlalchemy.orm.dynamic.AppenderBaseQuery object at 0x7f392e4ecb10>
>>> for user in users:
...     print user
... 
<User u'susan'>
<User u'david'>
>>> user_role.users.order_by(User.username).all()
[<User u'david'>, <User u'susan'>]
>>> str(user_role.users.order_by(User.username))
'SELECT users.id AS users_id, users.username AS users_username, users.role_id AS users_role_id \nFROM users \nWHERE ? = users.role_id ORDER BY users.username'

```

```
User.query.filter_by(nickname=nickname).first()
self.followed.filter(followers.c.followed_id == user.id).count()
u1.followed_posts().all()
```
只有在执行count() first() all()等方法时，查询才会真正执行
>> It is always a good idea to return query objects instead of results, because that gives the caller the choice of adding more clauses to the query before it is executed.

### database migration
在开发程序的过程中，你会发现有时需要修改数据库模型，而且修改之后还需要更新数据库。仅当数据库表不存在时， Flask-SQLAlchemy 才会根据模型进行创建。因此，更新表的唯一方式就是先删除旧表，不过这样做会丢失数据库中的所有数据
更新表的更好方法是使用数据库迁移框架。源码版本控制工具可以跟踪源码文件的变化，类似地，数据库迁移框架能跟踪数据库模式的变化，然后增量式的把变化应用到数据库中
```python
from flask.ext.migrate import Migrate, MigrateCommand
# ...
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
```
为了导出数据库迁移命令， Flask-Migrate 提供了一个 MigrateCommand 类，可附加到 FlaskScript 的 manager 对象上。在这个例子中， MigrateCommand 类使用 db 命令附加。
在维护数据库迁移之前，要使用 init 子命令创建迁移仓库：
```python
python hello.py db init
```

```
python hello.py db migrate -m "initial migration"
python hello.py db upgrade
```
## Flask-Mail电子邮件
```python
import os
# ...
app.config['MAIL_SERVER'] = 'smtp.qq.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')


from flask.ext.mail import Mail
mail = Mail(app)

from flask.ext.mail import Message
app.config['FLASKY_MAIL_SUBJECT_PREFIX'] = '[Flasky]'
app.config['FLASKY_MAIL_SENDER'] = '1549722424@qq.com'
def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
                  sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)
```
sender 参数一定要和你使用的代理邮件服务器邮箱账号一致，比如你使用了QQ邮箱代理服务器，那么用户名和密码就是QQ邮箱的用户名和授权码（可以查看QQ邮箱配置smtp）；to当然就是你要发给谁了。
把程序发送电子邮件的通用部分抽象出来，定义成一个函数send\_email。 这么做还有个好处，即该函数可以使用 Jinja2 模板渲染邮件正文，
灵活性极高。send\_email 函数的参数分别为收件人地址、主题、渲染邮件正文的模板和关键字参数列表。指定
模板时不能包含扩展名，这样才能使用两个模板分别渲染纯文本正文和富文本正文。

异步发送邮件，防止前端等待

```python
from threading import Thread
def send_async_email(app, msg):
    with app.app_context():
      mail.send(msg)
def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
                  sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr
```
## user authentication

### user password_hash(werkzeug)
密码安全性 werkzeug 实现密码散列存储；因为不同的用户也有可能存储相同的密码；
  - generate\_password\_hash(password, method=pbkdf2:sha1, salt\_length=8)：这个函数将原始密码作为输入，以字符串形式输出密码的散列值， 输出的值可保存在用户数据库中。method 和 salt\_length 的默认值就能满足大多数需求。
  - check\_password\_hash(hash, password)：这个函数的参数是从数据库中取回的密码散列值和用户输入的密码。返回值为 True 表明密码正确。

```python
from werkzeug.security import generate_password_hash, check_password_hash
class User(db.Model):
    # ...
    password_hash = db.Column(db.String(128))
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

```
[计算加盐密码散列值的正确方法](https://crackstation.net/hashing-security.htm)

### user login (flask-login)
使用flask-login 需要 User model实现以下四个函数：
|变量名       |说明 |
|------------|:---------------|
|is_authenticated |如果用户已经登录，必须返回 True，否则返回 False|
|is_active        |如果允许用户登录，必须返回 True，否则返回 False。如果要禁用账户，可以返回 False|
|is_anonymous     |对普通用户必须返回 False|
|get_id()         |必须返回用户的唯一标识符，使用 Unicode 编码字符串|
但是更简单的方式是继承UserMixin，该对象是flask-login 已经实现了最简单的以上四个方法，可以查看UserMixin源代码
```python
from flask.ext.login import UserMixin
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
```
flask-login 初始化

```python
from flask.ext.login import LoginManager
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'
def create_app(config_name):
    # ...
    login_manager.init_app(app)
```
最后，flask-login 还要求使用者 给出一个回调函数，用来加载用户

```python
from . import login_manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
```
### user register
用户注册表单

```python
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User
class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),Email()])
    username = StringField('Username', validators=[Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
    'Usernames must have only letters, '
    'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')
    
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')
```
注册

```python
form = RegistrationForm()
if form.validate_on_submit():
    user = User(email=form.email.data,
    username=form.username.data,
    password=form.password.data)
    db.session.add(user)
    flash('You can now login.')
    return redirect(url_for('auth.login'))
return render_template('auth/register.html', form=form)

```
### User confirmation 
用户在使用邮箱注册时，为了防止机器批量注册，必须使验证邮箱的有效性和并对用户进行验证，验证之后的用户才算是真实的用户；
现在大部分的用户验证都是在注册之后，根据用户的电子邮箱给用户发送一封电子邮件；邮件里包含的是用户在数据库中的id，但是id一般是被加密过得，以防止恶意使用他人id进行验证；
使用itsdangerous生成确认令牌；itsdangerous 提供了多种生成令牌的方法。其中， TimedJSONWebSignatureSerializer 类生成
具有过期时间的 JSON Web 签名（ JSON Web Signatures， JWS）。这个类的构造函数接收
的参数是一个密钥，在 Flask 程序中可使用 SECRET_KEY 设置

```python
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from . import db
class User(UserMixin, db.Model):
    # ...
    confirmed = db.Column(db.Boolean, default=False)
    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})
    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True
```
产生确认链接

```python
db.session.add(user)
db.session.commit()
token = user.generate_confirmation_token()
send_email(user.email, 'Confirm Your Account',
'auth/email/confirm', user=user, token=token)
flash('A confirmation email has been sent to you by email.')
return redirect(url_for('main.index'))
```

确认视图

```python
from flask.ext.login import current_user
@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))
```
[Setup User Authentication in Flask](http://blog.sampingchuang.com/setup-user-authentication-in-flask/)

## 防止用户提交后接着又刷新浏览器
用户提交表单后，接着又刷新浏览器，会导致浏览器再一次发送上一次发送的请求，这样就会提交两个一样的表单记录，为了防止这种事情发生，需要在处理表单请求成功后对浏览器进行重定向redirect


## 大型程序的结构
### 结构目录
### 配置选项
```python
import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
  
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    FLASKY_MAIL_SUBJECT_PREFIX = '[Flasky]'
    FLASKY_MAIL_SENDER = 'Flasky Admin <flasky@example.com>'
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN')
    
    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')

class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

```
配置类可以定义 init\_app() 类方法，其参数是程序实例。在这个方法中，可以执行对当前环境的配置初始化。现在，基类 Config 中的 init\_app() 方法为空。
在这个配置脚本末尾， config 字典中注册了不同的配置环境，而且还注册了一个默认配置;


# Flask源码疑惑
 - [Flask 中的上下文对象](https://segmentfault.com/a/1190000004859568)
 - [Flask 源码剖析——服务启动篇](https://segmentfault.com/a/1190000005788124)
 - [ Flask request，g，session的实现原理](http://blog.csdn.net/yueguanghaidao/article/details/39533841)
 - [Flask源码解读session 的实现与扩展](http://liuliqiang.info/post/flask-session-explore/)
 - [Charming Python: 从Flask的request说起](http://www.zlovezl.cn/articles/charming-python-start-from-flask-request/)
 - [Flask源码剖析](http://mingxinglai.com/cn/2016/08/flask-source-code/)
 - [flask1.0-source-code](https://github.com/pallets/flask/blob/0.1/flask.py)
 - [werkzeug/werkzeug/serving.py](https://github.com/pallets/werkzeug/blob/master/werkzeug/serving.py)
 - [Werkzeug 教程](http://werkzeug-docs-cn.readthedocs.io/zh_CN/latest/tutorial.html)
 - [how-to-set-up-a-firewall-with-ufw-on-ubuntu-16-04](https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-with-ufw-on-ubuntu-16-04)


所谓WSGI接口，或者说协议，就是双方都得遵守的编程接口，说的更直接就是，一个回调函数，这个函数的书写者遵循WSGI规范，
例如含有environment和start_response 两个参数的application函数，
 - environ：一个包含所有HTTP请求信息的dict对象；
 - start_response：一个发送HTTP响应的函。
 ```python
 def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [b'<h1>Hello, web!</h1>']
 ```
 那么他的调用者，也必须按照这个方式调用application，即要给他传递environment和response函数然他使用；这个就是底层的web server 需要做的，我们只负责 web app的业务逻辑的开发；
 
 python 内置的支持WSGI的服务器

```python
from wsgiref.simple_server import make_server
# 导入我们自己编写的application函数:
from hello import application

# 创建一个服务器，IP地址为空，端口是8000，处理函数是application:
httpd = make_server('', 8000, application)
print('Serving HTTP on port 8000...')
# 开始监听HTTP请求:
httpd.serve_forever()
```
Werkzeug服务器

```python
from hello import application
from werkzeug.serving import run_simple

run_simple('127.0.0.1', 5000, application, use_debugger=True, use_reloader=True)
```

## Python module & packages
一个 py 文件就是一个 module， 如果想要结构化的组织py文件，行程命名空间，那么这些 结构化的 py文件就组成了一个 package，package 可以包含package
每一个module都可以包含 可执行语句(executable statements)以及函数定义(function definitions)， 这些语句用来初始化模块，他们当且仅当模块初次导入时执行；模块内定义的全局变量对模块内是全局的，但是对其他模块是不可见的，除非导入，而且使用者可以使用和模块内同名的变量module1.name，因为使用者在另一个模块module2.name。
import模块之后，即使模块发生变化，也不能再加载了；reload() 可以动态的重新加载模块；

python fib.py 和 在 Python 解释器里 import fib 有什么不同？

每一个module 都有一个 \_\_name\_\_变量，并且\_\_name\_\_=modulename；import 并不会改变该模块的变量名字，因此你在一个模块中写这个我们所谓的执行入口，
如果是交互式，\_\_name\_\_=modulename，实际上是Python解释器读到这里，发现\_\_name\_\_并不等于\_\_main\_\_，就不会执行了；
但是如果直接执行fib.py, Python解释器会把\_\_name\_\_设置成\_\_main\_\_，所以就执行了module里的执行语句
```python
if __name__ == '__main__':
    import sys
    fib(int(sys.argv[1]))
```
对于package， 需要含有一个 \_\_init\_\_.py 文件，用于 导入时初始化执行；