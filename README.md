# ATM-SENTINEL AI: Anti-Theft Robbery Detection System 🛡️🎥

ATM-SENTINEL AI is an end-to-end intelligent surveillance platform that monitors live ATM CCTV/IP camera feeds in real time. Powered by **YOLOv8**, **OpenCV**, and a stateful behavior assessment engine, the system tracks individuals, detects hidden faces (masks) and weapons, monitors suspicious behavior (loitering and aggression), calculates a dynamic threat risk score, and sends instant security alerts (SMTP email notifications with attached evidence snapshot image) to response teams.

---

## Key Features
* 📺 **Real-time Video Streaming**: Multi-part MJPEG stream viewable directly in a web browser.
* 🧠 **YOLOv8 Object Detection**: High-accuracy detection of persons and weapons (knives, firearms) with confidence boundary scores.
* 👥 **Human Path Tracking**: A custom Centroid Tracking algorithm registers unique IDs for patrons.
* 🏃 **Behavior Telemetry**: Auto-detects loitering (duration > 60s), aggression (sudden high-velocity movements), and ATM ROI proximity.
* ⚡ **Stateful Risk Assessment Engine**: Computes threat levels (LOW, MEDIUM, HIGH) dynamically based on combined vector weights.
* 📧 **Automated Alarm Dispatcher**: Captures evidence snapshots of critical incidents and dispatches email alerts via SMTP.
* 📊 **Glassmorphic Admin Dashboard**: Modern dark-themed dashboard showing camera feeds, threat risk timelines, status indicators, and incident resolution control panels.
* ⚙️ **Dual-Mode Operation**:
  * **Real Feed Mode**: Uses local webcam (index 0) or IP camera stream and runs live computer vision logic.
  * **Interactive Simulation Mode**: Loops through an animated vector robbery scenario, showing how the risk score increases, alerts trigger, and alarms sound, making the project easy to demo in headless environments.

---

## System Architecture & Folder Structure

```
ATM-SENTINEL-AI/
│
├── app.py                      # Main Flask application entrypoint & routing
├── config.py                   # Configuration parameters (SMTP, thresholds, paths)
├── requirements.txt            # Python environment dependencies
├── database.db                 # SQLite database ledger (auto-generated)
│
├── detection/
│   └── detector.py            # YOLOv8 object inference & Haar cascades
├── tracking/
│   └── tracker.py             # Centroid tracking & coordinate logging
├── behavior/
│   └── analyzer.py            # Loitering, aggression, and ROI logic
├── alerts/
│   └── notifier.py            # SMTP dispatcher & evidence snapshot saver
├── database/
│   └── db_manager.py          # SQLite schema seeding & activity logs
│
├── static/
│   ├── css/
│   │   └── style.css          # Premium cyber-dark layout stylesheet
│   ├── js/
│   │   └── dashboard.js       # AJAX polling, dynamic metrics, Chart.js timeline
│   └── uploads/               # Directory storing warning evidence images
│
├── templates/
│   ├── index.html             # Landing portal showing system modules
│   ├── login.html             # Secure console login page
│   ├── dashboard.html         # Live surveillance control desk
│   └── alerts.html            # Alarm audit log ledger
│
├── tests/
│   └── test_app.py            # Automated unit tests
└── README.md                  # Setup documentation
```

---

## Threat Scoring Rules
The threat engine calculates scores based on active telemetry vectors:

| Telemetry Vector | Risk Score Weight | Description |
| :--- | :---: | :--- |
| **Weapon Detected** | **+70** | SUSPECT brandishing knife or firearm |
| **Mask / Covered Face** | **+20** | Hidden identity or mask worn by visitor |
| **Loitering Duration** | **+20** | Subject remaining in camera space for > 60 seconds |
| **Aggressive Movement** | **+30** | Sudden high-velocity centroid displacement |

### Threat Levels
* 🟢 **LOW RISK** (Score < 40): Normal monitoring.
* 🟡 **MEDIUM RISK** (Score 40 - 69): Warn operator on dashboard, log behavior.
* 🔴 **HIGH THREAT** (Score $\ge$ 70): Trigger visual flashing alarms on console, play sound alarm, save evidence snapshot, dispatch SMTP email notification.

---

## Getting Started

### 📋 Prerequisites
* Python 3.8 to 3.12 (standard installation).
* A camera/webcam connected (optional, fallback to simulation is automated).

### ⚙️ Installation & Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/ATM-SENTINEL-AI.git
   cd ATM-SENTINEL-AI
   ```

2. **Set up a Virtual Environment**:
   ```bash
   python -m venv venv
   # Activate on Windows:
   venv\Scripts\activate
   # Activate on Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: The `ultralytics` package automatically downloads the tiny model `yolov8n.pt` into the `models/` directory on the first execution of Real Mode).*

4. **Configure SMTP Email Alerts (Optional)**:
   To receive actual email alerts, define your SMTP settings in your environment variables or directly inside `config.py`:
   ```bash
   # Windows PowerShell:
   $env:SMTP_EMAIL="your-email@gmail.com"
   $env:SMTP_PASSWORD="your-app-password-from-google"
   $env:ALERT_RECEIVER="security-receiver@domain.com"
   ```
   *(If these environment variables are missing, the system will log a detailed MOCK alert in the terminal instead of sending an email, allowing full functionality).*

5. **Run the Database Migrations**:
   ```bash
   python database/db_manager.py
   ```
   This creates `database.db` and seeds the default administrator account:
   * **Username**: `admin`
   * **Password**: `admin123`

---

## Running the Application

1. **Start the Flask Server**:
   ```bash
   python app.py
   ```
2. **Access the Console**:
   * Open your web browser and go to `http://localhost:5000`.
   * Log in using `admin` / `admin123`.

3. **Demystifying the Interface Modes**:
   * **Dashboard Controls**: Check "Simulation Active" on the dashboard to review the automated robbery timeline loop. Uncheck it to activate your webcam for real YOLOv8 object tracking!
   * **Manual Mock Simulator**: Use the buttons on the right side of the dashboard to manually toggle specific threat signals (e.g. Weapon, Mask) and immediately trigger visual alerts and emails.

---

## Running Unit Tests
Execute the test suite using Python's built-in unittest framework:
```bash
python -m unittest tests/test_app.py
```

---

## Project Screenshots
Below is the visual overview of the glassmorphic dark theme dashboard:

### 1. Welcome Landing Portal
*Landing interface displaying the multi-stage system architecture modules.*

### 2. Live Surveillance Console
*CCTV feed viewport with real-time YOLOv8 bounding boxes, dynamic risk score meter, active vector indicators, threat risk timeline charts, and audit log table.*

### 3. Incident Audit Ledger
*Historical list of alerts stored in SQLite, allowing security personnel to filter by level, search descriptions, review evidence pictures in modals, and resolve pending cases.*

---

## License
Distributed under the MIT License. See `LICENSE` for more information.
