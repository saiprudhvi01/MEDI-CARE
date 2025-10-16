import os
from app import create_app, db
from config import config

# Create app instance using the application factory with production config
app = create_app(config['production'])

# Create tables if they don't exist
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
