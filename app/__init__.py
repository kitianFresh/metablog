# -*- coding: utf-8 -*-



import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_openid import OpenID
from config import basedir

app = Flask(__name__) # this app is a variable
app.config.from_object('config')
db = SQLAlchemy(app)


lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'
oid = OpenID(app, os.path.join(basedir, 'tmp'))
'''
这里的 import 语句放在后面是为了避免循环引用的问题，因为 views 模块需要引用 app variable
'''
from app import views, models # this app is a package from views




