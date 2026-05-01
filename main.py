import os
import sys
import json
import sqlite3
import hashlib
import pickle
import time
import random
import argparse
import threading
import queue
from datetime import datetime
from pathlib import Path
import getpass
import cv2
import numpy as np
import face_recognition
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from fpdf import FPDF
from flask import Flask, redirect, url_for, request, flash
try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None
import matplotlib
matplotlib.use('Agg')  # safe; FigureCanvasTkAgg will handle drawing
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd

# ---------------------- FILES & CONFIG ----------------------
DB_PATH = 'smart_voting.db'
LEDGER_PATH = 'vote_ledger.json'
ADMIN_CONFIG_PATH = 'admin_config.json'
CANDIDATES_PATH = 'candidates.json'

OTP_VALID_SECONDS = 180       # OTP validity seconds
FACE_TOLERANCE = 0.45        # face_recognition tolerance

# Blink liveness parameters (tunable via Settings)
EAR_THRESHOLD = 0.26
EAR_CONSEC_FRAMES = 2
BLINK_TIMEOUT_SECONDS = 15

# Auto-capture settings (tunable)
AUTO_CAPTURE_STABLE_FRAMES = 8
MIN_FACE_AREA_RATIO = 0.02
CENTER_TOLERANCE = 0.25

# Default candidates (will be overwritten by candidates.json if exists)
CANDIDATES = [
    {'id': 'C1', 'name': 'Alice'},
    {'id': 'C2', 'name': 'Bob'},
    {'id': 'C3', 'name': 'Carol'},
]

TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN', '')
TWILIO_FROM_NUMBER = os.getenv('TWILIO_FROM_NUMBER', '')
_diag_q = queue.Queue()
_diag_thread = None
_diag_stop_event = threading.Event()

# ---------------------- DATABASE ----------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS voters (
            voter_id TEXT PRIMARY KEY,
            name TEXT,
            phone TEXT,
            face_encoding BLOB,
            has_voted INTEGER DEFAULT 0,
            registered_at TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS votes (
            tx_hash TEXT PRIMARY KEY,
            voter_id TEXT,
            candidate_id TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

# ---------------------- LEDGER ----------------------
def load_ledger():
    if not Path(LEDGER_PATH).exists():
        return []
    with open(LEDGER_PATH, 'r') as f:
        return json.load(f)


def save_ledger(ledger):
    with open(LEDGER_PATH, 'w') as f:
        json.dump(ledger, f, indent=2)


def append_ledger(record):
    ledger = load_ledger()
    prev_hash = ledger[-1]['hash'] if len(ledger) else ''
    payload = json.dumps(record, sort_keys=True)
    combined = prev_hash + payload + str(time.time())
    tx_hash = hashlib.sha256(combined.encode()).hexdigest()
    ledger_entry = {'hash': tx_hash, 'prev': prev_hash, 'record': record, 'timestamp': datetime.utcnow().isoformat()}
    ledger.append(ledger_entry)
    save_ledger(ledger)
    return tx_hash

# ---------------------- OTP ----------------------
active_otps = {}  # voter_id -> (otp, expiry)


def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_twilio(voter_id, phone):
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER):
        return None
    if TwilioClient is None:
        print('twilio not installed; falling back to console OTP')
        return None
    try:
        client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        otp = generate_otp()
        expiry = time.time() + OTP_VALID_SECONDS
        active_otps[voter_id] = (otp, expiry)
        body = f'Your OTP for Smart Voting (valid {OTP_VALID_SECONDS}s): {otp}'
        message = client.messages.create(body=body, from_=TWILIO_FROM_NUMBER, to=phone)
        print('Sent SMS SID:', message.sid)
        return otp
    except Exception as e:
        print('Twilio send failed:', e)
        return None


def send_otp_console(voter_id, phone):
    otp = generate_otp()
    expiry = time.time() + OTP_VALID_SECONDS
    active_otps[voter_id] = (otp, expiry)
    print(f"[SIMULATED SMS] OTP for {voter_id} (to {phone}): {otp} (valid {OTP_VALID_SECONDS}s)")
    return otp


def send_otp(voter_id, phone):
    tw = send_otp_twilio(voter_id, phone)
    if tw:
        return tw
    return send_otp_console(voter_id, phone)

# ---------------------- CANDIDATES & ADMIN PASSWORD PERSISTENCE ----------------------
def load_candidates():
    global CANDIDATES
    if Path(CANDIDATES_PATH).exists():
        try:
            with open(CANDIDATES_PATH, 'r') as f:
                data = json.load(f)
                if isinstance(data, list) and all('id' in c and 'name' in c for c in data):
                    CANDIDATES = data
        except Exception:
            pass


def save_candidates():
    with open(CANDIDATES_PATH, 'w') as f:
        json.dump(CANDIDATES, f, indent=2)


def load_admin_config():
    if not Path(ADMIN_CONFIG_PATH).exists():
        return {}
    try:
        with open(ADMIN_CONFIG_PATH, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def save_admin_config(cfg):
    with open(ADMIN_CONFIG_PATH, 'w') as f:
        json.dump(cfg, f, indent=2)


def hash_password(pw, salt='smartvote_salt'):
    return hashlib.sha256((salt + pw).encode()).hexdigest()


def admin_password_exists():
    cfg = load_admin_config()
    return 'admin_hash' in cfg


def set_admin_password(new_password):
    cfg = load_admin_config()
    cfg['admin_hash'] = hash_password(new_password)
    save_admin_config(cfg)


def check_admin_password(entered_password):
    cfg = load_admin_config()
    if 'admin_hash' not in cfg:
        return False
    return cfg['admin_hash'] == hash_password(entered_password)


# ---------------------- ADMIN RESET UTILITIES ----------------------
def force_reset_admin_config():
    """
    Delete the admin_config.json file. Use with caution.
    """
    if Path(ADMIN_CONFIG_PATH).exists():
        try:
            os.remove(ADMIN_CONFIG_PATH)
            print(f"{ADMIN_CONFIG_PATH} removed. On next GUI start you'll be prompted to create a new admin password.")
            return True
        except Exception as e:
            print("Failed to remove admin config:", e)
            return False
    else:
        print("No admin config found; nothing to remove.")
        return True


def interactive_reset_admin():
    """
    Interactive flow to set a new admin password. If existing admin password is present,
    user must enter it (unless they choose to use force-reset).
    """
    if admin_password_exists():
        print("An admin password already exists.")
        # Ask for current password
        cur = getpass.getpass("Enter current admin password (leave empty to abort): ")
        if not cur:
            print("Aborted.")
            return False
        if not check_admin_password(cur):
            print("Incorrect current password. If you forgot it, re-run with --force-reset-admin.")
            return False
    # Ask for new password twice
    while True:
        p1 = getpass.getpass("Enter NEW admin password: ")
        p2 = getpass.getpass("Confirm NEW admin password: ")
        if not p1:
            print("Password cannot be empty. Try again.")
            continue
        if p1 != p2:
            print("Passwords do not match. Try again.")
            continue
        set_admin_password(p1)
        print("Admin password set successfully.")
        return True

# ---------------------- FACE UTILITIES ----------------------
def is_face_centered(box, frame_shape):
    top, right, bottom, left = box
    fh, fw = frame_shape[0:2]
    face_cx = (left + right) / 2.0
    face_cy = (top + bottom) / 2.0
    cx = fw / 2.0
    cy = fh / 2.0
    dx = abs(face_cx - cx) / fw
    dy = abs(face_cy - cy) / fh
    return dx < CENTER_TOLERANCE and dy < CENTER_TOLERANCE


def face_area_ratio(box, frame_shape):
    top, right, bottom, left = box
    fh, fw = frame_shape[0:2]
    area = (right - left) * (bottom - top)
    return area / (fw * fh)


def auto_capture_face_encoding(timeout=20):
    """
    Auto-capture face encoding: wait up to timeout, require centered + stable frames.
    """
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        raise RuntimeError('Cannot open webcam (camera in use?)')
    stable = 0
    last_box = None
    start = time.time()
    encoding = None
    while True:
        if time.time() - start > timeout:
            break
        ret, frame = cap.read()
        if not ret:
            continue
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        boxes = face_recognition.face_locations(rgb)
        display = frame.copy()
        if len(boxes) == 1:
            box = boxes[0]
            ar = face_area_ratio(box, frame.shape)
            centered = is_face_centered(box, frame.shape)
            if ar >= MIN_FACE_AREA_RATIO and centered:
                if last_box is not None:
                    prev_top, prev_right, prev_bottom, prev_left = last_box
                    top, right, bottom, left = box
                    move = abs(prev_top - top) + abs(prev_right - right) + abs(prev_bottom - bottom) + abs(prev_left - left)
                    if move < 40:
                        stable += 1
                    else:
                        stable = 1
                else:
                    stable = 1
                last_box = box
                top, right, bottom, left = box
                cv2.rectangle(display, (left, top), (right, bottom), (0, 200, 0), 2)
                cv2.putText(display, f'Stable: {stable}/{AUTO_CAPTURE_STABLE_FRAMES}', (10, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 200, 0), 2)
                if stable >= AUTO_CAPTURE_STABLE_FRAMES:
                    encs = face_recognition.face_encodings(rgb, boxes)
                    if encs:
                        encoding = encs[0]
                        break
            else:
                stable = 0
                cv2.putText(display, 'Center and move closer', (10, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 200), 2)
        else:
            stable = 0
            if len(boxes) > 1:
                cv2.putText(display, 'Multiple faces detected', (10, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 200), 2)
            else:
                cv2.putText(display, 'No face detected', (10, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 200), 2)
        cv2.imshow('Auto-capture Face (ESC to cancel)', display)
        if cv2.waitKey(1) & 0xFF == 27:
            break
    cap.release()
    try:
        cv2.destroyAllWindows()
    except Exception:
        pass
    return encoding


def compare_encoding_with_db(encoding):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT voter_id, face_encoding FROM voters')
    rows = c.fetchall()
    conn.close()
    for voter_id, enc_blob in rows:
        if enc_blob is None:
            continue
        try:
            stored = pickle.loads(enc_blob)
        except Exception:
            continue
        matches = face_recognition.compare_faces([stored], encoding, tolerance=FACE_TOLERANCE)
        if matches[0]:
            return voter_id
    return None

# ---------------------- BLINK LIVENESS ----------------------
def eye_aspect_ratio(eye):
    A = np.linalg.norm(np.array(eye[1]) - np.array(eye[5]))
    B = np.linalg.norm(np.array(eye[2]) - np.array(eye[4]))
    C = np.linalg.norm(np.array(eye[0]) - np.array(eye[3]))
    if C == 0:
        return 0.0
    ear = (A + B) / (2.0 * C)
    return ear


def liveness_check_blink_improved(timeout=BLINK_TIMEOUT_SECONDS):
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        return False
    consec_frames = 0
    total_blinks = 0
    ear_history = []
    start = time.time()
    while True:
        if time.time() - start > timeout:
            break
        ret, frame = cap.read()
        if not ret:
            continue
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        boxes = face_recognition.face_locations(rgb)
        landmarks = face_recognition.face_landmarks(rgb, boxes)
        display = frame.copy()
        if landmarks:
            lm = landmarks[0]
            left = lm.get('left_eye', None)
            right = lm.get('right_eye', None)
            if left and right:
                leftEAR = eye_aspect_ratio(left)
                rightEAR = eye_aspect_ratio(right)
                ear = (leftEAR + rightEAR) / 2.0
                ear_history.append(ear)
                if ear < EAR_THRESHOLD:
                    consec_frames += 1
                else:
                    if consec_frames >= EAR_CONSEC_FRAMES:
                        total_blinks += 1
                    consec_frames = 0
                cv2.putText(display, f'EAR:{ear:.2f} BLINKS:{total_blinks}', (10, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 200, 0), 2)
        else:
            cv2.putText(display, 'Face not found for blink detection', (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 200), 2)
        cv2.imshow('Blink Liveness (ESC to cancel)', display)
        if cv2.waitKey(1) & 0xFF == 27:
            break
        if total_blinks >= 1:
            break
    cap.release()
    try:
        cv2.destroyAllWindows()
    except Exception:
        pass
    return total_blinks >= 1

# ---------------------- REGISTRATION ----------------------
def register_voter_console():
    voter_id = input('Choose a numeric/alphanumeric Voter ID: ').strip()
    name = input('Full name: ').strip()
    phone = input('Mobile phone (for OTP simulation or Twilio): ').strip()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT voter_id FROM voters WHERE voter_id=?', (voter_id,))
    if c.fetchone():
        print('Voter ID already exists')
        conn.close()
        return
    conn.close()
    enc = auto_capture_face_encoding()
    if enc is None:
        print('Face capture failed or timed out')
        return
    dup = compare_encoding_with_db(enc)
    if dup:
        print('This face is already registered as:', dup)
        return
    enc_blob = pickle.dumps(enc)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO voters (voter_id, name, phone, face_encoding, registered_at) VALUES (?,?,?,?,?)',
              (voter_id, name, phone, enc_blob, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    print('Registration complete for', voter_id)

# ---------------------- AUTHENTICATION & VOTE ----------------------
def authenticate_voter(voter_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT phone, has_voted, face_encoding FROM voters WHERE voter_id=?', (voter_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, 'not_found'
    phone, has_voted, enc_blob = row
    if has_voted:
        return False, 'already_voted'
    # liveness
    alive = liveness_check_blink_improved()
    if not alive:
        return False, 'liveness_failed'
    # auto-capture face for verification
    enc = auto_capture_face_encoding()
    if enc is None:
        return False, 'face_capture_failed'
    if enc_blob is None:
        return False, 'no_face_on_record'
    try:
        stored = pickle.loads(enc_blob)
    except Exception:
        return False, 'corrupt_face_record'
    matches = face_recognition.compare_faces([stored], enc, tolerance=FACE_TOLERANCE)
    if not matches[0]:
        other = compare_encoding_with_db(enc)
        if other:
            return False, 'duplicate_face'
        return False, 'face_mismatch'
    # OTP
    otp = send_otp(voter_id, phone)
    if otp is None:
        otp = send_otp_console(voter_id, phone)
    # Use a GUI dialog for OTP input (better for demo)
    entered = simpledialog.askstring('OTP', f'Enter OTP sent to {phone} (console if simulated):')
    real, expiry = active_otps.get(voter_id, (None, 0))
    if real is None or time.time() > expiry or entered != real:
        return False, 'otp_failed'
    return True, 'ok'


def record_vote(voter_id, candidate_id):
    record = {'voter_id': voter_id, 'candidate_id': candidate_id, 'timestamp': datetime.utcnow().isoformat()}
    tx_hash = append_ledger(record)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO votes (tx_hash, voter_id, candidate_id, timestamp) VALUES (?,?,?,?)',
              (tx_hash, voter_id, candidate_id, datetime.utcnow().isoformat()))
    c.execute('UPDATE voters SET has_voted=1 WHERE voter_id=?', (voter_id,))
    conn.commit()
    conn.close()
    return tx_hash

# ---------------------- PDF Export ----------------------
def export_results_pdf(path='voting_report.pdf'):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT candidate_id, COUNT(*) FROM votes GROUP BY candidate_id')
    rows = c.fetchall()
    conn.close()
    counts = {c['id']: 0 for c in CANDIDATES}
    for cid, cnt in rows:
        counts[cid] = cnt
    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=12)
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Smart Voting System - Voting Report', ln=True, align='C')
    pdf.ln(8)
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 8, f'Date: {datetime.utcnow().isoformat()} UTC', ln=True)
    pdf.ln(6)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(80, 8, 'Candidate', border=1)
    pdf.cell(40, 8, 'Votes', border=1)
    pdf.ln()
    pdf.set_font('Arial', '', 12)
    for c in CANDIDATES:
        pdf.cell(80, 8, c['name'], border=1)
        pdf.cell(40, 8, str(counts.get(c['id'], 0)), border=1)
        pdf.ln()
    pdf.output(path)
    return path

# ---------------------- DIAGNOSTICS (Settings Window) ----------------------
def ear_diagnostic_worker(stop_event, q, show_frames=False):
    consec_frames = 0
    total_blinks = 0
    ear_history = []
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        q.put(('error', 'Cannot open webcam for diagnostics'))
        return
    while not stop_event.is_set():
        ret, frame = cap.read()
        if not ret:
            continue
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        boxes = face_recognition.face_locations(rgb)
        landmarks = face_recognition.face_landmarks(rgb, boxes)
        ear = None
        if landmarks:
            lm = landmarks[0]
            left = lm.get('left_eye', None)
            right = lm.get('right_eye', None)
            if left and right:
                leftEAR = eye_aspect_ratio(left)
                rightEAR = eye_aspect_ratio(right)
                ear = (leftEAR + rightEAR) / 2.0
                ear_history.append(ear)
                if ear < EAR_THRESHOLD:
                    consec_frames += 1
                else:
                    if consec_frames >= EAR_CONSEC_FRAMES:
                        total_blinks += 1
                    consec_frames = 0
        q.put(('update', {'ear': ear, 'blinks': total_blinks}))
        if show_frames:
            cv2.imshow('Diag', frame)
            if cv2.waitKey(1) & 0xFF == 27:
                break
        else:
            time.sleep(0.02)
    cap.release()
    try:
        cv2.destroyAllWindows()
    except Exception:
        pass
    q.put(('stopped', None))


class SettingsWindow(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title('Settings & Diagnostics')
        self.geometry('420x320')
        self.resizable(False, False)
        self.create_widgets()
        self.after(200, self.poll_diag_queue)

    def create_widgets(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # EAR slider
        ttk.Label(frm, text='EAR Threshold (lower = easier blink)').pack(anchor=tk.W, pady=(0, 4))
        self.ear_var = tk.DoubleVar(value=EAR_THRESHOLD)
        self.ear_slider = ttk.Scale(frm, from_=0.10, to=0.4, variable=self.ear_var, orient=tk.HORIZONTAL,
                                    command=self.on_ear_change)
        self.ear_slider.pack(fill=tk.X)
        self.ear_label = ttk.Label(frm, text=f'Current EAR_THRESHOLD = {EAR_THRESHOLD:.3f}')
        self.ear_label.pack(anchor=tk.W, pady=(2, 8))

        # Stable frames slider
        ttk.Label(frm, text='Auto-capture stable frames (frames required)').pack(anchor=tk.W, pady=(6, 4))
        self.stable_var = tk.IntVar(value=AUTO_CAPTURE_STABLE_FRAMES)
        self.stable_slider = ttk.Scale(frm, from_=3, to=20, variable=self.stable_var, orient=tk.HORIZONTAL,
                                       command=self.on_stable_change)
        self.stable_slider.pack(fill=tk.X)
        self.stable_label = ttk.Label(frm, text=f'Auto capture requires {AUTO_CAPTURE_STABLE_FRAMES} stable frames')
        self.stable_label.pack(anchor=tk.W, pady=(2, 8))

        # Blink timeout slider
        ttk.Label(frm, text='Blink timeout (seconds)').pack(anchor=tk.W, pady=(6, 4))
        self.blink_var = tk.IntVar(value=BLINK_TIMEOUT_SECONDS)
        self.blink_slider = ttk.Scale(frm, from_=5, to=60, variable=self.blink_var, orient=tk.HORIZONTAL,
                                      command=self.on_blink_change)
        self.blink_slider.pack(fill=tk.X)
        self.blink_label = ttk.Label(frm, text=f'Blink timeout = {BLINK_TIMEOUT_SECONDS} s')
        self.blink_label.pack(anchor=tk.W, pady=(2, 8))

        # Diagnostics controls
        hfrm = ttk.Frame(frm)
        hfrm.pack(fill=tk.X, pady=10)
        self.diag_btn = ttk.Button(hfrm, text='Start Diagnostics', command=self.toggle_diagnostics)
        self.diag_btn.pack(side=tk.LEFT)
        self.diag_status = ttk.Label(hfrm, text='Status: stopped')
        self.diag_status.pack(side=tk.LEFT, padx=10)

        ttk.Separator(frm).pack(fill=tk.X, pady=6)
        self.metrics_label = ttk.Label(frm, text='Live EAR: --    Blinks: 0', font=('Helvetica', 11))
        self.metrics_label.pack(anchor=tk.W, pady=6)

    def on_ear_change(self, _=None):
        global EAR_THRESHOLD
        new = float(self.ear_var.get())
        EAR_THRESHOLD = new
        self.ear_label.config(text=f'Current EAR_THRESHOLD = {EAR_THRESHOLD:.3f}')

    def on_stable_change(self, _=None):
        global AUTO_CAPTURE_STABLE_FRAMES
        new = int(self.stable_var.get())
        AUTO_CAPTURE_STABLE_FRAMES = new
        self.stable_label.config(text=f'Auto capture requires {AUTO_CAPTURE_STABLE_FRAMES} stable frames')

    def on_blink_change(self, _=None):
        global BLINK_TIMEOUT_SECONDS
        new = int(self.blink_var.get())
        BLINK_TIMEOUT_SECONDS = new
        self.blink_label.config(text=f'Blink timeout = {BLINK_TIMEOUT_SECONDS} s')

    def toggle_diagnostics(self):
        global _diag_thread, _diag_stop_event, _diag_q
        if _diag_thread and _diag_thread.is_alive():
            _diag_stop_event.set()
            self.diag_btn.config(text='Start Diagnostics')
            self.diag_status.config(text='Status: stopping...')
        else:
            _diag_stop_event.clear()
            while not _diag_q.empty():
                try:
                    _diag_q.get_nowait()
                except Exception:
                    break
            _diag_thread = threading.Thread(target=ear_diagnostic_worker, args=(_diag_stop_event, _diag_q), daemon=True)
            _diag_thread.start()
            self.diag_btn.config(text='Stop Diagnostics')
            self.diag_status.config(text='Status: running')

    def poll_diag_queue(self):
        try:
            while True:
                item = _diag_q.get_nowait()
                kind, data = item
                if kind == 'update':
                    ear = data.get('ear', None)
                    blinks = data.get('blinks', 0)
                    ear_text = f'{ear:.3f}' if ear is not None else '--'
                    self.metrics_label.config(text=f'Live EAR: {ear_text}    Blinks: {blinks}')
                elif kind == 'error':
                    self.metrics_label.config(text=f'Diagnostic error: {data}')
                elif kind == 'stopped':
                    self.diag_status.config(text='Status: stopped')
                    self.diag_btn.config(text='Start Diagnostics')
        except queue.Empty:
            pass
        finally:
            self.after(200, self.poll_diag_queue)

# ---------------------- ADMIN PASSWORD DIALOG ----------------------
class AdminPasswordDialog(simpledialog.Dialog):
    def body(self, master):
        if not admin_password_exists():
            ttk.Label(master, text='Create a new admin password:').grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0,6))
            ttk.Label(master, text='Password:').grid(row=1, column=0, sticky=tk.W)
            self.pw1 = ttk.Entry(master, show='*')
            self.pw1.grid(row=1, column=1)
            ttk.Label(master, text='Confirm:').grid(row=2, column=0, sticky=tk.W)
            self.pw2 = ttk.Entry(master, show='*')
            self.pw2.grid(row=2, column=1)
        else:
            ttk.Label(master, text='Enter admin password:').grid(row=0, column=0, sticky=tk.W, pady=(0,6))
            self.pw1 = ttk.Entry(master, show='*')
            self.pw1.grid(row=1, column=0, columnspan=2, sticky=tk.EW)
        return self.pw1

    def apply(self):
        if not admin_password_exists():
            p1 = self.pw1.get().strip()
            p2 = self.pw2.get().strip() if hasattr(self, 'pw2') else ''
            if not p1 or p1 != p2:
                messagebox.showerror('Error', 'Passwords empty or do not match. Admin password not set.')
                self.result = False
                return
            set_admin_password(p1)
            messagebox.showinfo('Admin password set', 'Admin password created successfully.')
            self.result = True
        else:
            entered = self.pw1.get().strip()
            if check_admin_password(entered):
                self.result = True
            else:
                messagebox.showerror('Invalid', 'Incorrect admin password')
                self.result = False

# ---------------------- MANAGE CANDIDATES ----------------------
class ManageCandidatesWindow(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title('Manage Candidates')
        self.geometry('420x320')
        self.create_widgets()
        self.load_list()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(frm, columns=('id', 'name'), show='headings', height=8)
        self.tree.heading('id', text='ID')
        self.tree.heading('name', text='Name')
        self.tree.column('id', width=80, anchor=tk.CENTER)
        self.tree.column('name', width=260, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True)

        btns = ttk.Frame(frm)
        btns.pack(fill=tk.X, pady=(8, 0))
        ttk.Button(btns, text='Add', command=self.add_candidate).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text='Edit', command=self.edit_candidate).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text='Remove', command=self.remove_candidate).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text='Save & Close', command=self.save_and_close).pack(side=tk.RIGHT, padx=6)

    def load_list(self):
        self.tree.delete(*self.tree.get_children())
        for c in CANDIDATES:
            self.tree.insert('', tk.END, values=(c['id'], c['name']))

    def add_candidate(self):
        cid = simpledialog.askstring('Candidate ID', 'Enter candidate ID (e.g. C4):', parent=self)
        if not cid:
            return
        name = simpledialog.askstring('Candidate Name', 'Enter candidate name:', parent=self)
        if not name:
            return
        # prevent duplicate IDs
        if any(c['id'] == cid.strip() for c in CANDIDATES):
            messagebox.showerror('Error', 'Candidate ID already exists')
            return
        CANDIDATES.append({'id': cid.strip(), 'name': name.strip()})
        self.load_list()

    def edit_candidate(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select a candidate first')
            return
        item = self.tree.item(sel[0])['values']
        cid, name = item[0], item[1]
        new_name = simpledialog.askstring('Edit candidate', f'New name for {cid}:', initialvalue=name, parent=self)
        if new_name:
            for c in CANDIDATES:
                if c['id'] == cid:
                    c['name'] = new_name.strip()
            self.load_list()

    def remove_candidate(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select a candidate first')
            return
        item = self.tree.item(sel[0])['values']
        cid = item[0]
        if messagebox.askyesno('Confirm', f'Remove candidate {cid}?'):
            global CANDIDATES
            CANDIDATES = [c for c in CANDIDATES if c['id'] != cid]
            self.load_list()

    def save_and_close(self):
        save_candidates()
        messagebox.showinfo('Saved', 'Candidates saved.')
        self.destroy()

# ---------------------- ADMIN DASHBOARD (Professional) ----------------------
class AdminDashboardWindow(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title('Admin Dashboard — Smart Voting System')
        self.geometry('980x620')
        self.minsize(900, 560)
        self._create_widgets()
        self.refresh_all()

    def _create_widgets(self):
        top = ttk.Frame(self, padding=(12, 8))
        top.pack(fill=tk.X)
        ttk.Label(top, text='Election Admin Dashboard', font=('Helvetica', 16, 'bold')).pack(side=tk.LEFT)
        bframe = ttk.Frame(top)
        bframe.pack(side=tk.RIGHT)
        ttk.Button(bframe, text='Refresh', command=self.refresh_all).pack(side=tk.LEFT, padx=6)
        ttk.Button(bframe, text='Export CSV', command=self.export_csv).pack(side=tk.LEFT, padx=6)
        ttk.Button(bframe, text='Export PDF', command=self.export_pdf_ui).pack(side=tk.LEFT, padx=6)
        ttk.Button(bframe, text='Export Ledger', command=self.export_ledger).pack(side=tk.LEFT, padx=6)
        ttk.Button(bframe, text='Close', command=self.destroy).pack(side=tk.LEFT, padx=6)

        main = ttk.Frame(self, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        search_frame = ttk.Frame(left)
        search_frame.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(search_frame, text='Search voter (ID or name):').pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))
        self.search_entry.bind('<Return>', lambda e: self.load_voters())
        ttk.Button(search_frame, text='Search', command=self.load_voters).pack(side=tk.LEFT, padx=6)
        ttk.Button(search_frame, text='Clear', command=self._clear_search).pack(side=tk.LEFT)

        cols = ('voter_id', 'name', 'phone', 'registered_at', 'has_voted')
        self.tree = ttk.Treeview(left, columns=cols, show='headings', selectmode='browse')
        for col, heading, width in [
            ('voter_id', 'Voter ID', 100),
            ('name', 'Name', 180),
            ('phone', 'Phone', 110),
            ('registered_at', 'Registered At', 160),
            ('has_voted', 'Has Voted', 80),
        ]:
            self.tree.heading(col, text=heading)
            self.tree.column(col, width=width, anchor=tk.CENTER if col in ('voter_id', 'phone', 'has_voted') else tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True)

        vbtn_frame = ttk.Frame(left)
        vbtn_frame.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(vbtn_frame, text='Revoke Vote', command=self.revoke_vote).pack(side=tk.LEFT, padx=6)
        ttk.Button(vbtn_frame, text='View Details', command=self.show_voter_details).pack(side=tk.LEFT, padx=6)

        right = ttk.Frame(main)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        fig = Figure(figsize=(5, 3), dpi=100)
        self.ax = fig.add_subplot(111)
        self.ax.set_title('Vote counts')
        self.ax.set_ylabel('Votes')
        self.canvas = FigureCanvasTkAgg(fig, master=right)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        ledger_frame = ttk.LabelFrame(right, text='Ledger (recent transactions)', padding=6)
        ledger_frame.pack(fill=tk.BOTH, expand=False)
        self.ledger_list = tk.Listbox(ledger_frame, height=8)
        self.ledger_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ledger_scroll = ttk.Scrollbar(ledger_frame, orient=tk.VERTICAL, command=self.ledger_list.yview)
        ledger_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.ledger_list.config(yscrollcommand=ledger_scroll.set)

        self.status_var = tk.StringVar(value='Ready')
        status = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status.pack(side=tk.BOTTOM, fill=tk.X)

    def _clear_search(self):
        self.search_var.set('')
        self.load_voters()

    def load_voters(self):
        filter_text = self.search_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if filter_text:
            q = f"%{filter_text}%"
            c.execute("SELECT voter_id, name, phone, registered_at, has_voted FROM voters WHERE LOWER(voter_id) LIKE ? OR LOWER(name) LIKE ? ORDER BY registered_at DESC", (q, q))
        else:
            c.execute('SELECT voter_id, name, phone, registered_at, has_voted FROM voters ORDER BY registered_at DESC')
        rows = c.fetchall()
        conn.close()
        for r in rows:
            vid, name, phone, reg, hv = r
            self.tree.insert('', tk.END, values=(vid, name, phone, reg, 'Yes' if hv else 'No'))

        self.status_var.set(f'Loaded {len(rows)} voters')

    def refresh_chart(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT candidate_id, COUNT(*) FROM votes GROUP BY candidate_id')
        rows = c.fetchall()
        conn.close()
        counts = {c['id']: 0 for c in CANDIDATES}
        for cid, cnt in rows:
            counts[cid] = cnt
        names = [c['name'] for c in CANDIDATES]
        vals = [counts[c['id']] for c in CANDIDATES]
        self.ax.clear()
        bars = self.ax.bar(names, vals)
        self.ax.set_title('Vote counts')
        self.ax.set_ylabel('Votes')
        for bar, v in zip(bars, vals):
            self.ax.text(bar.get_x() + bar.get_width() / 2, v + 0.05, str(v), ha='center', va='bottom')
        self.canvas.draw()
        self.status_var.set('Chart refreshed')

    def load_ledger_list(self):
        self.ledger_list.delete(0, tk.END)
        ledger = load_ledger()
        for e in ledger[-50:][::-1]:
            ts = e.get('timestamp', '')[:19]
            rec = e.get('record', {})
            txt = f"{ts} | {rec.get('voter_id')} -> {rec.get('candidate_id')} | {e.get('hash')[:10]}..."
            self.ledger_list.insert(tk.END, txt)
        self.status_var.set(f'Loaded ledger ({min(50, len(ledger))} recent entries)')

    def refresh_all(self):
        self.load_voters()
        self.refresh_chart()
        self.load_ledger_list()

    def get_selected_voter_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select voter', 'Please select a voter from the table')
            return None
        return self.tree.item(sel[0])['values'][0]

    def show_voter_details(self):
        vid = self.get_selected_voter_id()
        if not vid:
            return
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT voter_id, name, phone, registered_at, has_voted FROM voters WHERE voter_id=?', (vid,))
        row = c.fetchone()
        conn.close()
        if not row:
            messagebox.showinfo('Not found', 'Voter not found')
            return
        has_voted = 'Yes' if row[4] else 'No'
        messagebox.showinfo('Voter details', f'ID: {row[0]}\nName: {row[1]}\nPhone: {row[2]}\nRegistered: {row[3]}\nHas voted: {has_voted}')

    def revoke_vote(self):
        vid = self.get_selected_voter_id()
        if not vid:
            return
        if not messagebox.askyesno('Confirm', f'Revoke vote for {vid}? This will delete their vote and allow them to vote again.'):
            return
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM votes WHERE voter_id=?', (vid,))
        c.execute('UPDATE voters SET has_voted=0 WHERE voter_id=?', (vid,))
        conn.commit()
        conn.close()
        messagebox.showinfo('Revoked', f'Vote revoked for {vid}')
        self.refresh_all()

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files', '*.csv')])
        if not path:
            return
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query('SELECT voter_id, name, phone, registered_at, has_voted FROM voters', conn)
        conn.close()
        df.to_csv(path, index=False)
        messagebox.showinfo('Exported', f'Voters CSV saved to {path}')

    def export_pdf_ui(self):
        path = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF files', '*.pdf')])
        if not path:
            return
        export_results_pdf(path)
        messagebox.showinfo('Exported', f'PDF saved to {path}')

    def export_ledger(self):
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON files', '*.json')])
        if not path:
            return
        ledger = load_ledger()
        with open(path, 'w') as f:
            json.dump(ledger, f, indent=2)
        messagebox.showinfo('Exported', f'Ledger saved to {path}')

# ---------------------- MAIN APP GUI ----------------------
class SmartVotingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Smart Voting System (Enhanced)')
        self.geometry('680x520')
        self.create_widgets()

    def create_widgets(self):
        # style tweaks
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure('TButton', padding=6, font=('Helvetica', 11))
        style.configure('TLabel', font=('Helvetica', 11))

        frm = ttk.Frame(self, padding=18)
        frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frm, text='Smart Voting System - AI Driven', font=('Helvetica', 18, 'bold')).pack(pady=6)

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Button(btn_frame, text='Register Voter', command=self.register_window).pack(fill=tk.X, pady=6)
        ttk.Button(btn_frame, text='Vote (Voter Login)', command=self.vote_window).pack(fill=tk.X, pady=6)
        ttk.Button(btn_frame, text='Manage Candidates', command=self.manage_candidates).pack(fill=tk.X, pady=6)
        ttk.Button(btn_frame, text='Admin Dashboard', command=self.open_admin).pack(fill=tk.X, pady=6)
        ttk.Button(btn_frame, text='Settings & Diagnostics', command=lambda: SettingsWindow(self)).pack(fill=tk.X, pady=6)
        ttk.Button(btn_frame, text='Exit', command=self.quit).pack(fill=tk.X, pady=12)

    def register_window(self):
        win = tk.Toplevel(self)
        win.title('Register Voter')
        win.geometry('450x340')
        ttk.Label(win, text='Voter ID:').pack(pady=2)
        vid = ttk.Entry(win)
        vid.pack()
        ttk.Label(win, text='Full Name:').pack(pady=2)
        name = ttk.Entry(win)
        name.pack()
        ttk.Label(win, text='Phone (for OTP):').pack(pady=2)
        phone = ttk.Entry(win)
        phone.pack()

        def do_register():
            v = vid.get().strip()
            n = name.get().strip()
            p = phone.get().strip()
            if not v or not n:
                messagebox.showerror('Error', 'Voter ID and name required')
                return
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT voter_id FROM voters WHERE voter_id=?', (v,))
            if c.fetchone():
                messagebox.showerror('Error', 'Voter ID exists')
                conn.close()
                return
            conn.close()
            messagebox.showinfo('Capture', 'We will open webcam and auto-capture your face. Hold still.')
            try:
                enc = auto_capture_face_encoding()
            except Exception as e:
                messagebox.showerror('Error', f'Camera error: {e}')
                return
            if enc is None:
                messagebox.showerror('Error', 'Face capture failed or cancelled')
                return
            dup = compare_encoding_with_db(enc)
            if dup:
                messagebox.showerror('Error', f'This face is already registered as {dup}')
                return
            enc_blob = pickle.dumps(enc)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('INSERT INTO voters (voter_id, name, phone, face_encoding, registered_at) VALUES (?,?,?,?,?)',
                      (v, n, p, enc_blob, datetime.utcnow().isoformat()))
            conn.commit()
            conn.close()
            messagebox.showinfo('Success', f'Registered {v}')
            win.destroy()

        ttk.Button(win, text='Register & Auto-Capture Face', command=do_register).pack(pady=12)

    def vote_window(self):
        win = tk.Toplevel(self)
        win.title('Voter Login & Vote')
        win.geometry('520x420')
        ttk.Label(win, text='Enter your Voter ID:').pack(pady=6)
        vid = ttk.Entry(win)
        vid.pack()

        def start_vote():
            v = vid.get().strip()
            if not v:
                messagebox.showerror('Error', 'Enter voter ID')
                return
            ok, reason = authenticate_voter(v)
            if not ok:
                messagebox.showerror('Authentication Failed', f'Reason: {reason}')
                return
            sel = tk.StringVar()
            cand_win = tk.Toplevel(win)
            cand_win.title('Choose Candidate')
            ttk.Label(cand_win, text='Select a candidate:').pack(pady=6)
            for c in CANDIDATES:
                ttk.Radiobutton(cand_win, text=c['name'], variable=sel, value=c['id']).pack(anchor=tk.W)
            def submit_vote():
                cid = sel.get()
                if not cid:
                    messagebox.showerror('Error', 'Select a candidate')
                    return
                tx = record_vote(v, cid)
                messagebox.showinfo('Vote Recorded', f'Your vote tx hash:\n{tx}')
                cand_win.destroy()
                win.destroy()
            ttk.Button(cand_win, text='Submit Vote', command=submit_vote).pack(pady=10)

        ttk.Button(win, text='Authenticate & Vote', command=start_vote).pack(pady=12)

    def manage_candidates(self):
        ManageCandidatesWindow(self)

    def open_admin(self):
        dlg = AdminPasswordDialog(self)
        if getattr(dlg, 'result', False):
            AdminDashboardWindow(self)
        else:
            return

# ---------------------- FLASK WEB APP (Optional) ----------------------
app = Flask(__name__)
app.secret_key = 'dev-secret'

@app.route('/')
def index():
    return '<h3>Smart Voting System - Web mode</h3><p>Use /register or /vote (server webcam used). Not intended for production.</p>'

# (web routes left minimal; the GUI is primary for the demo)

# ---------------------- QUICK CONSOLE DEMO (fallback) ----------------------
def quick_demo():
    print('Quick demo menu:')
    print('1) Register (console)')
    print('2) Vote (console)')
    print('3) Show results')
    print('4) Export PDF report')
    print('q) quit')
    while True:
        c = input('Choose: ').strip()
        if c == '1':
            register_voter_console()
        elif c == '2':
            vid = input('Enter voter id: ').strip()
            ok, reason = authenticate_voter(vid)
            if ok:
                print('Candidates:')
                for cand in CANDIDATES:
                    print(cand['id'], cand['name'])
                cid = input('Choose candidate id: ').strip()
                tx = record_vote(vid, cid)
                print('Vote tx:', tx)
        elif c == '3':
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute('SELECT candidate_id, COUNT(*) FROM votes GROUP BY candidate_id')
            for row in cur.fetchall():
                print(row)
            conn.close()
        elif c == '4':
            path = input('Enter PDF path (default voting_report.pdf): ').strip()
            if not path:
                path = 'voting_report.pdf'
            export_results_pdf(path)
        elif c == 'q':
            break

# ---------------------- MAIN ----------------------
def main():
    init_db()
    if not Path(LEDGER_PATH).exists():
        save_ledger([])
    load_candidates()

    parser = argparse.ArgumentParser(description='Smart Voting System (Enhanced)')
    parser.add_argument('--web', action='store_true', help='Run as Flask web server (uses server webcam)')
    parser.add_argument('--reset-admin', action='store_true', help='Interactive reset/set admin password (prompts)')
    parser.add_argument('--force-reset-admin', action='store_true', help='Force delete admin_config.json (use when admin password lost)')
    parser.add_argument('--set-admin', metavar='PASSWORD', help='Set admin password non-interactively (WARNING: password will appear in shell history)')
    args = parser.parse_args()

    # Handle admin management CLI flags first, then continue to normal app launch
    if args.force_reset_admin:
        print("WARNING: This will delete the admin configuration file and cannot be undone.")
        confirm = input("Type 'DELETE-ADMIN' to confirm deletion: ").strip()
        if confirm == 'DELETE-ADMIN':
            ok = force_reset_admin_config()
            if ok:
                print("Admin config removed. Start the GUI to create a new admin password.")
            else:
                print("Failed to remove admin config. Check file permissions.")
        else:
            print("Aborted force reset.")
        return

    if args.reset_admin:
        success = interactive_reset_admin()
        if not success:
            print("Admin reset not completed.")
        return

    if args.set_admin:
        pw = args.set_admin
        set_admin_password(pw)
        print("Admin password set via --set-admin. Start GUI and log in with the provided password.")
        return

    if args.web:
        print('Starting Flask server at http://127.0.0.1:5000')
        app.run(debug=True)
        return

    # Start GUI
    try:
        root = SmartVotingApp()
        root.mainloop()
    except Exception as e:
        print('GUI failed, falling back to console demo. Error:', e)
        quick_demo()


if __name__ == '__main__':
    main()






# Good luck! If you want, I can now:
# - Customize the PDF design (logo, more stats)
# - Add client-side webcam capture (so the web page can capture face images in-browser)
# - Replace server-side webcam in Flask with file upload flow
# Tell me which next and I will update the code in the canvas.




