import os

class Config:
    # Flask security
    SECRET_KEY = os.environ.get('SECRET_KEY', 'atm-sentinel-secret-key-993881')
    
    # Paths
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.path.join(BASE_DIR, 'database.db')
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    
    # SMTP Email configuration (fallback to local mock if not defined)
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_EMAIL = os.environ.get('SMTP_EMAIL', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')  # Use App Password
    ALERT_RECEIVER = os.environ.get('ALERT_RECEIVER', '')
    
    # Threat score weights
    THREAT_WEAPON = 70
    THREAT_MASK = 20
    THREAT_LOITERING = 20
    THREAT_AGGRESSION = 30
    
    # Alert thresholds
    HIGH_THREAT_THRESHOLD = 70
    MEDIUM_THREAT_THRESHOLD = 40
    
    # Behavior rules
    LOITERING_THRESHOLD_SECS = 60  # seconds loitering before scoring
    AGGRESSION_VELOCITY_THRESHOLD = 50.0  # pixels/frame threshold for sudden movements
