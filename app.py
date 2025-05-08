from flask import Flask, render_template, request, redirect, flash, session, url_for
import firebase_admin
from firebase_admin import credentials, firestore
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import requests
from bs4 import BeautifulSoup
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
# Add these imports
from firebase_admin import auth
from werkzeug.security import generate_password_hash
from datetime import datetime


# --- Flask setup ---
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'



# --- Firebase setup ---
firebase_creds = {
    "type": "service_account",
    "project_id": "nibmexamalerts",
    "private_key_id": "e6911ca83aa203eeaedaebf33f898f32f593efa7",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD2nxXZcAmGUIsV\nAp7OG4by0uN9wkhXJYmdwd7XQE/Hmqkh35t4BiSpmG/r+yNj7PW/NidyM49a8vn1\nzUkk17ec3Cq1t699onumC1FiO+vWu8GX6Y9gHc66Zq2x2PYF3We7DTjtLoQgsmkO\nlyosssyCTfT1Ysh0Xg5eTvhpBNFGvfZc0W1vlhmHjjDMtDkxjcY1mKcrmud+e6k1\nfC1PeuKmYUwlBdYewUr6Py5C08abeV5VE8lfNs9PhQ59J+Efn9c7tOrH5wYvfQEd\nnP/KeY6fEcGyVqIrcJwHogYwrlUl7CykJb8RD0TliWu99XcgAOyQ8BwEh7W30a8N\nYLu32eK9AgMBAAECggEAXqztz15iWay75+HsowUQRlHNQW7/JG1lqilN6eZneiIW\ngcl8vpPlKTI67SWpDWhfYvtgI0hF5U1XxhP722fwtggTYVVVym5A95pqsMJ+JB5K\nEI56GxT2UrquPZMjx1aaxsUpsGvmD0NOb2p6p1QwjGlu+3DjsUCWVYANfwt5Z6Uu\nbNmuUHJQwJke69/nAg73GLORpJsrxKfaPtxEi3eiHBDNsEvGjuNeqOfnCMj38jeT\nExazi1obev0qn1PY5aolgajqOqSl522zINmHV6qUMnFKv3BXO249FfnVTQeJk5R/\nOSdK6XLZQgkOYai8KZYYb59P1L3rWFxB1l7UMs90hQKBgQD8+KiAPORzwqXRCRsq\nIV/6vTWYZPOWv9y56eU5/pSfplKUmei1aTh8WPD97OAUzSep8PoUuGw+qzCmZ0YQ\nvXMNdepMY7r6bIpkH+x3Wvnl7O9WQugAbe0E/zA0v8/P38UnPpAphUAxz1Vs/ZUA\nRA0jmRXizcwaVDTQNCc8UNPFVwKBgQD5kvcQ5EGlafZZgZzqnaA0QjzLjmgP4QHJ\n5NMAOJGL7fd6p0tqqAW5OooclrUZU9BIQGMvZTxGiMnvYZdzYug5sUtOgncSq3T+\nYhpQMduLDhViGNwkPZscJ3B44GmPSQqdGovoJDyyJeFJQf+jWjmWVr1SMY5ggHvu\nXAVnk1nYCwKBgFdNFRGUch7FCOZ35wkGFZJ5o7pg9HOM6Qa8AmCeS/pAsvUXnGim\n1FiNdTWcfsSO/GY4hIWME8cY2yRCNbrnNoJptB8Ct+9eb/AX2EpkeiNwPjSdyGUF\niquTybYakAQkLGzbuXKqyrml3MxNQxOhaItldFkePpbDgqprpTK6jirnAoGBAJTS\ndlG0SxEAZs5o49FjvSxscyRO/u65Ff/2W3w+P0xZ0sFpESfAmekiZ0k09TjtKb5r\n5rlUfOTynLgKUe2UhTYh6u4eDjMr2s/2YAqCMJBzDX05pcxWkC/xtLff2hJ/U7zr\nH5KGSUtSG0079dzK6JwljS9+LZCODVjNtstUqraRAoGAdmC8qEhnLHIgixX4eCsh\nNPwJANsg1vTlbyS/DK9cFJtslBCtx0CfvDGg4eYxiwrIKAIoPVAcLcGsNQKbVd0G\nSOATOj1hyKlY8tbYeSgQ5esFD38TFZkBcS8KDnoaT7r5PPrtFqnY8+gc6THkU7gj\na005CRylucGN2sFu+1OtA+k=\n-----END PRIVATE KEY-----\n".replace('\\n', '\n'),
    "client_email": "firebase-adminsdk-fbsvc@nibmexamalerts.iam.gserviceaccount.com",
    "client_id": "115641182921293882201",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40nibmexamalerts.iam.gserviceaccount.com"
}

cred = credentials.Certificate(firebase_creds)
firebase_admin.initialize_app(cred)
db = firestore.client()
USERS_COLLECTION = 'users'

ALLOWED_BRANCHES = ['CO', 'KU', 'MT', 'KD', 'DE']

# --- SMTP Config (MailerSend) ---
SMTP_SERVER = "smtp.mailersend.net"
SMTP_PORT = 587
SMTP_USERNAME = "MS_7jOtRM@test-65qngkdd3yolwr12.mlsender.net"
SMTP_PASSWORD = "mssp.UXlI3FX.3vz9dle9ej1gkj50.vk4Qp8O"
SENDER_EMAIL = "no-reply@test-65qngkdd3yolwr12.mlsender.net"

# --- Helper: Send Email via SMTP ---
def send_email(to_email, subject, html_content):
    message = MIMEMultipart()
    message["From"] = SENDER_EMAIL
    message["To"] = to_email
    message["Subject"] = subject
    message.attach(MIMEText(html_content, "html"))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, message.as_string())
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# --- Scraping Logic ---
def scrape_exams():
    url = 'https://www.nibmworldwide.com/exams'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    table_body = soup.select_one('.examlst tbody')
    exams = []
    if table_body:
        for row in table_body.find_all('tr'):
            cols = row.find_all('td')
            if len(cols) > 1:
                date_time_raw = cols[0].get_text(strip=True)
                code_name = cols[1].get_text(strip=True)
                match_dt = re.match(r'(\d{4}-\d{2}-\d{2})(\d{2}:\d{2}\s*[ap]m)', date_time_raw, re.IGNORECASE)
                date = match_dt.group(1) if match_dt else date_time_raw
                time = match_dt.group(2).replace(' ', '') if match_dt else ''
                match_code = re.match(r'^([A-Z0-9.]+)\/([A-Z]{2})(.*)', code_name)
                if match_code:
                    code_part = match_code.group(1)  # e.g. "ADDS24.2F"
                    branch = match_code.group(2)     # e.g. "CO" (exactly 2 letters)
                    name = match_code.group(3).strip()  # Remaining text after branch
                    code = f"{code_part}/{branch}"
                else:
                    code = code_name
                    name = ''
                exams.append({
                    'date': date,
                    'time': time,
                    'code': code,
                    'name': name
                })
    return exams

# --- Scheduler Job: Check Exams and Notify ---
def check_exams():
    scraped_exams = scrape_exams()
    users_ref = db.collection(USERS_COLLECTION)
    users = users_ref.stream()
    for user_doc in users:
        user = user_doc.to_dict()
        matches = []
        for reg_exam in user.get('exams', []):
            user_code = reg_exam['code'].strip().upper()
            user_name = reg_exam['name'].strip().lower()
            if '/' in user_code:
                user_code_part, user_branch = user_code.split('/', 1)
                for exam in scraped_exams:
                    exam_code = exam['code'].strip().upper()
                    exam_name = exam['name'].strip().lower()
                    if '/' in exam_code:
                        exam_code_part, exam_branch = exam_code.split('/', 1)
                        # Apply all three matching conditions
                        if (
                            user_code_part in exam_code_part and
                            user_branch == exam_branch and
                            user_name in exam_name
                        ):
                            matches.append(exam)
        if matches and not user.get('notification_sent', False):
            send_exam_notification(user['email'], matches)
            users_ref.document(user_doc.id).update({'notification_sent': True})
            # In check_exams() when sending notifications:
            notification_ref = users_ref.document(user_doc.id).collection('notifications').document()
            notification_ref.set({
                'timestamp': firestore.SERVER_TIMESTAMP,
                'exams': [exam['code'] for exam in matches],
                'sent': True
            })


# --- Email Templates ---
def send_exam_notification(email, exams):
    html_content = "<h2>New exams matching your criteria:</h2><ul>"
    for exam in exams:
        html_content += (
            f"<li><b>Date:</b> {exam['date']}<br>"
            f"<b>Time:</b> {exam['time']}<br>"
            f"<b>Code:</b> {exam['code']}<br>"
            f"<b>Name:</b> {exam['name']}</li><br>"
        )
    html_content += "</ul>"
    send_email(email, "Exam Notification", html_content)

def send_registration_confirmation(email, exams):
    if exams:
        html_content = "<h2>Thank you for registering for exam alerts!</h2>"
        html_content += "<p>The following matching exams are currently scheduled:</p><ul>"
        for exam in exams:
            print(exam)
            html_content += (
                f"<li><b>Exam Name:</b> {exam['name']}<br>"
                f"<b>Date:</b> {exam['date']}<br>"
                f"<b>Time:</b> {exam['time']}<br>"
                f"<b>Code:</b> {exam['code']}</li><br>"
            )
        html_content += "</ul>"
    else:
        html_content = (
            "<h2>Thank you for registering for exam alerts!</h2>"
            "<p>No matching exams are scheduled yet. "
            "We will notify you as soon as a matching exam is scheduled.</p>"
        )
    
    send_email(email, "Exam Registration Confirmation", html_content)

# --- Scheduler Setup ---
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_exams, trigger=CronTrigger(hour='9,21', minute=0), name='daily_exam_check')
scheduler.start()

# --- Routes ---
@app.route('/')
def home():
    return redirect('/register')


# Modified register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        code_parts = request.form.getlist('code_part[]')
        branches = request.form.getlist('branch[]')
        exam_names = request.form.getlist('exam_name[]')

        # Validation
        if not all([username, email, password, confirm_password, code_parts, branches, exam_names]):
            flash('All fields are required', 'error')
            return redirect('/register')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect('/register')

        try:
            # Create Firebase Auth user
            user = auth.create_user(
                email=email,
                password=password
            )
            
            # Check if username exists in Firestore
            users_ref = db.collection('users').document(username)
            if users_ref.get().exists:
                auth.delete_user(user.uid)  # Rollback auth creation
                flash('Username already taken', 'error')
                return redirect('/register')

            # Build exams list
            exams = []
            for code_part, branch, exam_name in zip(code_parts, branches, exam_names):
                if branch not in ALLOWED_BRANCHES:
                    flash(f'Invalid branch: {branch}', 'error')
                    return redirect('/register')
                exams.append({
                    'code': f"{code_part.strip().upper()}/{branch}",
                    'name': exam_name.strip()
                })

            # Create Firestore document with username as ID
            users_ref.set({
                'uid': user.uid,
                'email': email,
                'exams': exams,
                'notification_sent': False
            })

            # Scrape and check for matches
            scraped_exams = scrape_exams()
            matches = []
            for crit in exams:
                for exam in scraped_exams:
                    user_code_parts = crit['code'].split('/')
                    if len(user_code_parts) != 2:
                        continue
                    user_code_part, user_branch = user_code_parts
                    exam_code_parts = exam['code'].split('/')
                    if len(exam_code_parts) != 2:
                        continue
                    exam_code_part, exam_branch = exam_code_parts
                    if (user_code_part in exam_code_part and 
                        user_branch == exam_branch and 
                        crit['name'].lower() in exam['name'].lower()):
                        matches.append(exam)

            send_registration_confirmation(email, matches)
            flash('Registration successful! You will receive email alerts when exams are scheduled.', 'success')
            return redirect('/register')

        except auth.EmailAlreadyExistsError:
            flash('Email already registered', 'error')
            return redirect('/register')
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'error')
            return redirect('/register')

    return render_template('register.html', branches=ALLOWED_BRANCHES)

@app.route("/test-email")
def test_email():
    try:
        send_email("muneebasmone2001@outlook.com", "Test Email from Flask",
                   "<p>This is a test email sent from Flask using MailerSend SMTP.</p>")
        return "Email sent successfully!"
    except Exception as e:
        return f"Error: {e}"

@app.route('/profile')
def profile():
    if 'user_email' not in session:
        flash('Please log in to view your profile.', 'error')
        return redirect('/login')
    email = session['user_email']
        
    user_ref = db.collection(USERS_COLLECTION).where('email', '==', email).limit(1)
    user_doc = user_ref.get()[0] if user_ref.get() else None
    
    if not user_doc:
        flash('User not found', 'error')
        return redirect('/register')
    
    user_data = user_doc.to_dict()
    
    # Get notifications
    notifications = []
    noti_ref = user_doc.reference.collection('notifications').order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
    for noti in noti_ref:
        notifications.append(noti.to_dict())
    
    # Check current exam matches
    scraped_exams = scrape_exams()
    matches = []
    for crit in user_data.get('exams', []):
        for exam in scraped_exams:
            user_code_parts = crit['code'].split('/')
            if len(user_code_parts) != 2:
                continue
            user_code_part, user_branch = user_code_parts
            exam_code_parts = exam['code'].split('/')
            if len(exam_code_parts) != 2:
                continue
            exam_code_part, exam_branch = exam_code_parts
            if (user_code_part in exam_code_part and 
                user_branch == exam_branch and 
                crit['name'].lower() in exam['name'].lower()):
                matches.append(exam)
    
    return render_template(
        'profile.html',
        user=user_data,
        notifications=notifications,
        current_matches=matches,
        branches=ALLOWED_BRANCHES
    )

@app.route('/update_email', methods=['POST'])
def update_email():
    old_email = request.form.get('old_email')
    new_email = request.form.get('new_email')
    password = request.form.get('password')

    # Validate and update Firestore
    users_ref = db.collection(USERS_COLLECTION)
    user_doc = users_ref.where('email', '==', old_email).limit(1).get()[0]

    # Update Firestore
    user_doc.reference.update({'email': new_email})

    # Update Firebase Authentication
    try:
        # Update the user's email in Firebase Auth
        user = auth.get_user_by_email(old_email)
        auth.update_user(user.uid, email=new_email)
        flash('Email updated successfully', 'success')
    except Exception as e:
        flash(f'Failed to update email in Firebase Auth: {str(e)}', 'error')

    return redirect(f'/profile?email={new_email}')

@app.route('/update_exams', methods=['POST'])
def update_exams():
    email = request.form.get('email')
    new_exams = []
    
    # Process exam fields same as registration
    code_parts = request.form.getlist('code_part[]')
    branches = request.form.getlist('branch[]')
    exam_names = request.form.getlist('exam_name[]')
    
    for cp, br, en in zip(code_parts, branches, exam_names):
        new_exams.append({
            'code': f"{cp.upper()}/{br}",
            'name': en.strip()
        })
    
    # Update Firestore
    users_ref = db.collection(USERS_COLLECTION)
    user_doc = users_ref.where('email', '==', email).limit(1).get()[0]
    user_doc.reference.update({'exams': new_exams})
    
    flash('Exams updated successfully', 'success')
    return redirect(f'/profile?email={email}')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    flash('Logged out.', 'success')
    return redirect('/login')

import requests
from flask import session

FIREBASE_WEB_API_KEY = "AIzaSyCp3g_FFC750veJGNUMbB5TH9llUMAHSuA"  # Replace with your actual key

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Look up the user document by username (which is the document ID)
        user_doc_ref = db.collection(USERS_COLLECTION).document(username)
        user_doc = user_doc_ref.get()

        if user_doc.exists:
            user_email = user_doc.to_dict().get('email')  # Get the email from the user document

            # Firebase Auth REST API endpoint
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
            payload = {
                "email": user_email,
                "password": password,
                "returnSecureToken": True
            }

            resp = requests.post(url, json=payload)
            data = resp.json()

            if resp.status_code == 200:
                # Login successful
                session['user_email'] = user_email
                flash('Login successful!', 'success')
                return redirect('/profile')
            else:
                error_message = data.get('error', {}).get('message', 'Login failed.')
                flash(f'Login failed: {error_message}', 'error')
                return redirect('/login')
        else:
            flash('Username not found.', 'error')
            print(f"Debug: Username '{username}' not found in Firestore.")  # Debugging line
            return redirect('/login')

    return render_template('login.html')

@app.route('/remove_exam', methods=['POST'])
def remove_exam():
    exam_code = request.form.get('exam_code')
    email = session.get('user_email')

    if not email:
        flash('You must be logged in to remove an exam.', 'error')
        return redirect('/login')

    # Update Firestore
    users_ref = db.collection(USERS_COLLECTION)
    user_doc = users_ref.where('email', '==', email).limit(1).get()[0]

    # Get current exams
    current_exams = user_doc.to_dict().get('exams', [])
    
    # Remove the exam with the specified code
    updated_exams = [exam for exam in current_exams if exam['code'] != exam_code]

    # Update Firestore with the new list of exams
    user_doc.reference.update({'exams': updated_exams})

    flash('Exam removed successfully.', 'success')
    return redirect('/profile')

@app.template_filter('datetime')
def format_datetime(value):
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')  # Adjust the format as needed
    return value
