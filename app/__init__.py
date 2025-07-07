from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
bootstrap = Bootstrap()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    bootstrap.init_app(app)

    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.scans import bp as scans_bp
    app.register_blueprint(scans_bp)

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    return app