import os
from app import create_app, db
from flask_migrate import Migrate
from app.models import User

app = create_app(os.getenv('FLASK_CONFIG') or 'default')

migrate = Migrate(app, db)

@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User)

@app.cli.command()
def test():
    """Run the unit tests."""
    import unittest
    test = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(test)