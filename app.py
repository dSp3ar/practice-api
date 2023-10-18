from logging.config import dictConfig

from flasgger import Swagger
from flask import Flask
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

import config
from admin_views import MyAdminIndexView

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)
CORS(app)

app.config.from_object(config.Config)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

from models import User, BlacklistToken, Subject, StudentsSubjects

admin = Admin(app, name='Admin panel', template_mode='bootstrap4', index_view=MyAdminIndexView())

admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(BlacklistToken, db.session))
admin.add_view(ModelView(Subject, db.session))
admin.add_view(ModelView(StudentsSubjects, db.session))

swagger = Swagger(app)
migrate = Migrate(app, db)
