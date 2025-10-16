from application import create_app, db
from app.models import User, Patient, Hospital, AmbulanceDriver, BookingRequest

app = create_app()

@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'Patient': Patient,
        'Hospital': Hospital,
        'AmbulanceDriver': AmbulanceDriver,
        'BookingRequest': BookingRequest
    }

if __name__ == '__main__':
    app.run(debug=True)
