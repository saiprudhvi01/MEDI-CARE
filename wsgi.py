import os
from app import app, db, create_app
from flask_migrate import Migrate

# Create app instance using the application factory
app = create_app()

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
