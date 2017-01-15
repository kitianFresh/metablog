# -*- coding: utf-8 -*-

from flask import Flask

app = Flask(__name__) # this app is a variable

'''
这里的 import 语句放在后面是为了避免循环引用的问题，因为 views 模块需要引用 app variable
'''
from app import views # this app is a package from views


