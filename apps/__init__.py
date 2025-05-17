# -*- encoding: utf-8 -*-

import os

from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from importlib import import_module
from flask_migrate import Migrate
from flask_restx import Api


db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()


def register_extensions(app):
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)


def register_blueprints(app):
    """Register Flask blueprints."""
    from apps.api.routes import blueprint as api_blueprint
    from apps.authentication.routes import blueprint as auth_blueprint
    from apps.home.routes import blueprint as home_blueprint

    app.register_blueprint(api_blueprint)
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(home_blueprint)


def configure_database(app):

    @app.before_first_request
    def initialize_database():
        try:
            db.create_all()
        except Exception as e:

            print('> Error: DBMS Exception: ' + str(e) )

            # fallback to SQLite
            basedir = os.path.abspath(os.path.dirname(__file__))
            app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'db.sqlite3')

            print('> Fallback to SQLite ')
            db.create_all()

    @app.teardown_request
    def shutdown_session(exception=None):
        db.session.remove()

from apps.authentication.oauth import github_blueprint

def create_app(config):
    """Create Flask application."""
    app = Flask(__name__)
    
    # Configurar limite de tamanho da requisição para 100MB
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB em bytes
    
    # Carregar configurações
    app.config.from_object(config)
    
    # Inicializar extensões
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    
    # Registrar blueprints
    register_blueprints(app)
    
    app.register_blueprint(github_blueprint, url_prefix="/login") 
    
    configure_database(app)
    return app
