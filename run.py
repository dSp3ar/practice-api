from app import app
from auth import auth_blueprint
from subjects import subject_blueprint

app.register_blueprint(auth_blueprint)
app.register_blueprint(subject_blueprint)

if __name__ == '__main__':
    app.run()
