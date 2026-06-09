import os
import time
import cv2
import numpy as np
from flask import Flask, render_template, Response, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash

from config import Config
from database.db_manager import init_db, get_db_connection, log_activity
from detection.detector import ATMDetector
from tracking.tracker import CentroidTracker
from behavior.analyzer import BehaviorAnalyzer
from alerts.notifier import AlertNotifier

app = Flask(__name__)
app.config.from_object(Config)

# Initialize global modules
detector = ATMDetector(use_yolo=True, simulation_mode=True)
tracker = CentroidTracker()
analyzer = BehaviorAnalyzer()
notifier = AlertNotifier()

# Global state for threat scoring and simulated injects
system_state = {
    'threat_score': 0,
    'simulation_mode': True,
    'last_alert_trigger_time': 0,
    'vectors': {
        'weapon': False,
        'mask': False,
        'loitering': False,
        'aggression': False
    },
    'forced_vectors': {
        'weapon': False,
        'mask': False,
        'loitering': False,
        'aggression': False
    }
}

# Session authentication decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """System Landing page."""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Secure login endpoint."""
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            log_activity("USER_LOGIN", f"User '{username}' logged in successfully.")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password credentials', 'error')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logs the user out."""
    username = session.get('username', 'Unknown')
    session.clear()
    log_activity("USER_LOGOUT", f"User '{username}' logged out.")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main real-time surveillance console."""
    conn = get_db_connection()
    camera = conn.execute('SELECT * FROM cameras LIMIT 1').fetchone()
    conn.close()
    
    return render_template('dashboard.html', active_camera=camera)

@app.route('/alerts')
@login_required
def alerts_history():
    """Incident logs audit ledger browser."""
    threat_level = request.args.get('threat_level', '')
    status = request.args.get('status', '')
    search = request.args.get('search', '')
    
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    
    if threat_level:
        query += " AND threat_level = ?"
        params.append(threat_level)
    if status == 'resolved':
        query += " AND is_resolved = 1"
    elif status == 'unresolved':
        query += " AND is_resolved = 0"
    if search:
        query += " AND description LIKE ?"
        params.append(f"%{search}%")
        
    query += " ORDER BY timestamp DESC"
    
    conn = get_db_connection()
    alerts = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('alerts.html', alerts=alerts)

@app.route('/resolve_alert/<int:alert_id>', methods=['POST'])
@app.route('/api/resolve_alert/<int:alert_id>', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    """Marks a pending alert as resolved in the database."""
    conn = get_db_connection()
    conn.execute('UPDATE alerts SET is_resolved = 1 WHERE id = ?', (alert_id,))
    conn.commit()
    conn.close()
    
    log_activity("ALERT_RESOLVED", f"Alert ID {alert_id} resolved by {session.get('username')}.")
    
    if request.path.startswith('/api/'):
        return jsonify({'status': 'success', 'message': f'Alert {alert_id} resolved.'})
    
    flash(f'Alert ID {alert_id} marked as resolved.', 'success')
    return redirect(url_for('alerts_history'))

# ==================== WEB API ENDPOINTS ====================

@app.route('/api/telemetry', methods=['GET'])
@login_required
def api_telemetry():
    """Returns real-time telemetry metrics for AJAX dashboard polling."""
    # Get 5 recent alerts
    conn = get_db_connection()
    recent_alerts = conn.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5').fetchall()
    conn.close()
    
    alerts_list = []
    for alert in recent_alerts:
        alerts_list.append({
            'id': alert['id'],
            'timestamp': alert['timestamp'],
            'threat_level': alert['threat_level'],
            'threat_score': alert['threat_score'],
            'description': alert['description'],
            'image_path': alert['image_path'],
            'is_resolved': bool(alert['is_resolved'])
        })
        
    return jsonify({
        'threat_score': system_state['threat_score'],
        'simulation_mode': system_state['simulation_mode'],
        'vectors': system_state['vectors'],
        'recent_alerts': alerts_list
    })

@app.route('/api/config', methods=['POST'])
@login_required
def api_config():
    """Updates system configurations dynamically."""
    data = request.json
    if 'simulation_mode' in data:
        system_state['simulation_mode'] = bool(data['simulation_mode'])
        detector.simulation_mode = system_state['simulation_mode']
        log_activity("CONFIG_CHANGE", f"Simulation Mode toggled to: {detector.simulation_mode}")
    return jsonify({'status': 'success'})

@app.route('/api/simulator', methods=['POST'])
@login_required
def api_simulator():
    """Handles manual simulation signals injection."""
    data = request.json
    vector = data.get('vector', '')
    
    if vector == 'reset':
        for k in system_state['forced_vectors']:
            system_state['forced_vectors'][k] = False
        log_activity("SIMULATOR_RESET", "Manual simulator triggers cleared.")
    elif vector in system_state['forced_vectors']:
        # Toggle forced state
        system_state['forced_vectors'][vector] = not system_state['forced_vectors'][vector]
        log_activity("SIMULATOR_TRIGGER", f"Mock vector '{vector}' toggled to: {system_state['forced_vectors'][vector]}")
        
    return jsonify({'status': 'success'})

# ==================== VIDEO STREAM GENERATOR ====================

def generate_lobby_frame(elapsed, score, vectors):
    """
    Synthesizes a realistic vector-based lobby scene in case of simulated modes
    or webcam absence. Automatically draws UI layouts and dynamic movements.
    """
    # 640x480 canvas
    frame = np.zeros((480, 640, 3), dtype=np.uint8)
    
    # Draw lobby backgrounds (Deep Slate Blue)
    cv2.rectangle(frame, (0, 0), (640, 480), (33, 26, 20), -1)
    
    # Draw ATM Kiosk Frame (Gray Kiosk Body)
    cv2.rectangle(frame, (420, 100), (580, 420), (70, 70, 70), -1)
    cv2.rectangle(frame, (430, 120), (570, 240), (150, 150, 150), -1) # ATM Screen
    cv2.rectangle(frame, (450, 280), (550, 300), (30, 30, 30), -1) # Cash dispenser slot
    cv2.circle(frame, (470, 350), 15, (50, 50, 50), -1) # ATM dome camera
    
    # Display system text on ATM screen
    cv2.putText(frame, "ATM ACTIVE", (450, 180), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 0), 1, cv2.LINE_AA)
    
    # Draw lobby entrance door (Left side)
    cv2.rectangle(frame, (10, 50), (140, 430), (50, 40, 30), 2)
    cv2.putText(frame, "ENTRY DOOR", (25, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (200, 200, 200), 1, cv2.LINE_AA)
    
    # Draw floor grid guidelines
    for y in range(300, 480, 30):
        cv2.line(frame, (0, y), (640, y), (45, 35, 25), 1)
        
    # Animate walking person based on the simulation elapsed timeline
    # 0s - 15s: Empty lobby
    # 15s - 45s: Walks from entry door (left) to ATM (right)
    # 45s - 98s: Interacts with ATM
    # 98s - 110s: Runs away back to the left
    # 110s - 120s: Empty lobby
    
    person_pos = None
    if 15.0 <= elapsed < 45.0:
        # Interpolate walk from (80, 240) to (320, 240)
        alpha = (elapsed - 15.0) / 30.0
        x = int(80 + alpha * (320 - 80))
        person_pos = (x, 240)
    elif 45.0 <= elapsed < 98.0:
        # Standard stationary position near ATM
        # Aggressive movement adds pixel vibrations/tremors
        x_vib = 0
        y_vib = 0
        if vectors['aggression']:
            # Rapid vibratory movements to show struggle
            x_vib = int(np.random.randint(-15, 16))
            y_vib = int(np.random.randint(-15, 16))
        person_pos = (320 + x_vib, 240 + y_vib)
    elif 98.0 <= elapsed < 110.0:
        # Escape path back to the left
        alpha = (elapsed - 98.0) / 12.0
        x = int(320 - alpha * (320 - 50))
        person_pos = (x, 240)
        
    if person_pos:
        px, py = person_pos
        # Draw Person Body (Circle and rectangles)
        cv2.circle(frame, (px, py - 60), 22, (200, 180, 150), -1) # Head
        cv2.rectangle(frame, (px - 25, py - 35), (px + 25, py + 80), (180, 50, 50), -1) # Torso
        
        # Draw mask on face if active
        if vectors['mask']:
            cv2.rectangle(frame, (px - 15, py - 62), (px + 15, py - 46), (30, 30, 30), -1) # Black mask block
            cv2.putText(frame, "MASK", (px - 18, py - 70), cv2.FONT_HERSHEY_SIMPLEX, 0.35, (0, 165, 255), 1, cv2.LINE_AA)
            
        # Draw Weapon in hand if active
        if vectors['weapon']:
            # Draw weapon (Red outline representing handgun/knife)
            cv2.line(frame, (px - 35, py), (px - 55, py + 10), (0, 0, 255), 4) # Gun barrel
            cv2.line(frame, (px - 45, py + 5), (px - 45, py + 20), (0, 0, 255), 4) # Handle
            cv2.putText(frame, "WEAPON", (px - 70, py - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 0, 255), 1, cv2.LINE_AA)

    # Draw CCTV UI details (Timestamp, Camera ID, threat score overlay)
    cv2.putText(frame, "CCTV CAM_01 - LOBBY FRONT", (20, 450), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1, cv2.LINE_AA)
    cv2.putText(frame, f"TIME: {time.strftime('%Y-%m-%d %H:%M:%S')}", (20, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1, cv2.LINE_AA)
    
    # Draw flashing red alert border if high threat score
    if score >= Config.HIGH_THREAT_THRESHOLD:
        flash_state = int(time.time() * 2) % 2
        if flash_state == 0:
            cv2.rectangle(frame, (0, 0), (640, 480), (0, 0, 255), 6)
            cv2.putText(frame, "ALARM TRIGGERED", (230, 50), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2, cv2.LINE_AA)
            
    return frame

def video_stream_generator():
    """Generates JPEG frame stream with detections and threat assessments overlays."""
    cap = None
    webcam_failed = False
    
    # Try opening webcam if simulation mode is NOT forced
    if not system_state['simulation_mode']:
        try:
            # camera 0
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                webcam_failed = True
                print("Could not open system webcam. Streaming synthetic lobby feed instead.")
        except Exception as e:
            webcam_failed = True
            print(f"Webcam initialization exception: {e}. Falling back to synthetic feed.")
            
    start_time = time.time()
    
    while True:
        elapsed = (time.time() - start_time) % 120
        
        # 1. Resolve Active Threat Vectors (Simulated vs Real)
        vectors = {
            'weapon': False,
            'mask': False,
            'loitering': False,
            'aggression': False
        }
        
        # Inject manual GUI mock triggers
        for key in vectors:
            if system_state['forced_vectors'][key]:
                vectors[key] = True
                
        # Inject automated timeline simulation variables
        if system_state['simulation_mode'] or webcam_failed:
            if 15.0 <= elapsed < 100.0:
                # Person loitering if duration > loitering threshold
                if elapsed > 15.0 + Config.LOITERING_THRESHOLD_SECS:
                    vectors['loitering'] = True
            if 45.0 <= elapsed < 100.0:
                vectors['mask'] = True
            if 70.0 <= elapsed < 98.0:
                vectors['weapon'] = True
                vectors['aggression'] = True
        
        # Compute final threat score
        score = 0
        if vectors['weapon']: score += Config.THREAT_WEAPON
        if vectors['mask']: score += Config.THREAT_MASK
        if vectors['loitering']: score += Config.THREAT_LOITERING
        if vectors['aggression']: score += Config.THREAT_AGGRESSION
        score = min(score, 100)
        
        system_state['threat_score'] = score
        system_state['vectors'] = vectors
        
        # Capture and Process Frame
        frame = None
        if not system_state['simulation_mode'] and cap and cap.isOpened():
            ret, cap_frame = cap.read()
            if ret:
                # Run Frame Preprocessor
                preprocessed = detector.preprocess_frame(cap_frame)
                
                # Execute YOLO Detection
                detections = detector.detect(preprocessed)
                
                # Extract person coordinates for tracking
                person_rects = []
                for det in detections:
                    if det['label'] == 'person':
                        person_rects.append(det['box'])
                        
                # Update Tracker
                tracked_bboxes = tracker.update(person_rects)
                
                # Run Behavior Analysis on tracked coordinates
                behavior_results = analyzer.analyze(tracker)
                
                # Overwrite/Add detected values to vectors
                for obj_id, bh in behavior_results.items():
                    if bh['loitering']:
                        vectors['loitering'] = True
                    if bh['aggression']:
                        vectors['aggression'] = True
                
                for det in detections:
                    if det['label'] == 'weapon':
                        vectors['weapon'] = True
                    elif det['label'] == 'mask':
                        vectors['mask'] = True
                        
                # Re-calculate threat score based on real camera detections
                real_score = 0
                if vectors['weapon']: real_score += Config.THREAT_WEAPON
                if vectors['mask']: real_score += Config.THREAT_MASK
                if vectors['loitering']: real_score += Config.THREAT_LOITERING
                if vectors['aggression']: real_score += Config.THREAT_AGGRESSION
                real_score = min(real_score, 100)
                
                system_state['threat_score'] = real_score
                system_state['vectors'] = vectors
                
                # Draw boxes and labels on preprocessed camera frame
                frame = detector.draw_detections(preprocessed, detections)
                frame = analyzer.draw_roi(frame)
            else:
                # Capture stream error fallback
                frame = generate_lobby_frame(elapsed, score, vectors)
        else:
            # Simulation / Headless Mode Frame Synthesis
            frame = generate_lobby_frame(elapsed, score, vectors)
            
            # Draw overlay boxes in simulation mode to make it look like active AI detection
            if 15.0 <= elapsed < 100.0:
                # Draw Person green box
                cv2.rectangle(frame, (230, 90), (430, 450), (0, 255, 0), 2)
                cv2.putText(frame, "PERSON: 0.94", (230, 85), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 0), 1, cv2.LINE_AA)
            if vectors['mask'] and (15.0 <= elapsed < 100.0):
                # Draw Mask orange box
                cv2.rectangle(frame, (280, 110), (360, 195), (0, 165, 255), 2)
                cv2.putText(frame, "MASK: 0.88", (280, 105), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 165, 255), 1, cv2.LINE_AA)
            if vectors['weapon'] and (70.0 <= elapsed < 98.0):
                # Draw weapon red box
                cv2.rectangle(frame, (210, 220), (290, 280), (0, 0, 255), 2)
                cv2.putText(frame, "WEAPON (GUN): 0.82", (210, 215), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 255), 1, cv2.LINE_AA)
                
            frame = analyzer.draw_roi(frame)
            
        # 2. Check Threat Risk and Generate Alerts
        # Trigger alert if threat score exceeds HIGH threshold and cooldown isn't active
        if system_state['threat_score'] >= Config.HIGH_THREAT_THRESHOLD:
            now = time.time()
            # 30-second cooldown between alert events of same sequence
            if now - system_state['last_alert_trigger_time'] > 30:
                system_state['last_alert_trigger_time'] = now
                
                # Assemble alert description
                desc_items = []
                if vectors['weapon']: desc_items.append("Weapon detected")
                if vectors['mask']: desc_items.append("Suspect face covered")
                if vectors['loitering']: desc_items.append("Prolonged loitering")
                if vectors['aggression']: desc_items.append("Aggressive movements/struggle")
                
                description = "ATM robbery risk detected! " + ", ".join(desc_items)
                
                # Capture snapshot as evidence
                image_path = notifier.save_evidence_snapshot(frame, system_state['threat_score'])
                
                # Log Alert to DB
                notifier.log_alert_to_db(
                    camera_id=1,
                    threat_level='HIGH',
                    threat_score=system_state['threat_score'],
                    description=description,
                    image_path=image_path
                )
                
                # Dispatch SMTP Email Notification
                notifier.send_email_alert(
                    threat_level='HIGH',
                    threat_score=system_state['threat_score'],
                    description=description,
                    image_path=image_path
                )
                
        # Encode frame to JPG
        ret, jpeg = cv2.imencode('.jpg', frame)
        if ret:
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + jpeg.tobytes() + b'\r\n')
                   
        time.sleep(0.04) # Stream around ~25 FPS

@app.route('/video_feed')
def video_feed():
    """MJPEG streaming endpoint for displaying live surveillance video."""
    return Response(video_stream_generator(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# ==================== MAIN INITIALIZATION ====================

if __name__ == '__main__':
    # Initialize SQLite database and seed admin
    init_db()
    
    # Run server
    print("Launching ATM-SENTINEL AI Server...")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
