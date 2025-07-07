import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'scanner.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BOOTSTRAP_SERVE_LOCAL = True
    OPENVAS_SOCKET = os.environ.get('OPENVAS_SOCKET', '/run/gvmd/gvmd.sock')
    OPENVAS_USER = os.environ.get('OPENVAS_USER', 'admin')
    OPENVAS_PASSWORD = os.environ.get('OPENVAS_PASSWORD', '')