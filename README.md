# MEDI-CARE

A Hospital Management System built with Python Flask that connects patients with hospitals based on bed availability, specialty, and location.

## Features

- Patient and Hospital user roles
- Real-time bed availability tracking
- Specialty-based hospital search
- Booking request system
- Ambulance availability
- Doctor availability
- Disease prediction based on symptoms

## Setup

1. Clone the repository:
   ```
   git clone https://github.com/saiprudhvi01/MEDI-CARE.git
   cd MEDI-CARE
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up the database:
   ```
   flask db upgrade
   ```

5. Run the application:
   ```
   flask run
   ```

## Deployment

This application is deployed on Render. You can access it at [https://medi-care.onrender.com](https://medi-care.onrender.com)

## License

MIT
"# Hospital-Management-System" 
