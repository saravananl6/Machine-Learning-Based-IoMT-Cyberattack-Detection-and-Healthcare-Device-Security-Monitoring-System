from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import json
import os
import hashlib
import uuid
from datetime import datetime
import random

app = Flask(__name__)
app.secret_key = "iomt_secret_key_2024"

# ── Data storage (JSON files for portability) ──────────────────────────────────
USERS_FILE = "users.json"
PREDICTIONS_FILE = "predictions.json"

def load_json(path, default):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ── ML Model ───────────────────────────────────────────────────────────────────
try:
    import joblib, pandas as pd, numpy as np
    model  = joblib.load("best_iomt_attack_model.pkl")
    scaler = joblib.load("scaler.pkl")
    ML_AVAILABLE = True
    print("[IoMT] ML model loaded successfully.")
except Exception as e:
    ML_AVAILABLE = False
    print(f"[IoMT] ML model not found, using heuristic fallback. ({e})")

attack_map = {
    0: "Normal",
    1: "DoS",
    2: "MITM",
    3: "Replay",
    4: "Spoofing",
    5: "Data Falsification"
}

# Severity weight per class — used to compute the final dynamic risk score
# from the model's probability vector. Higher weight = more dangerous class.
ATTACK_SEVERITY_WEIGHTS = {
    "Normal":             0.05,
    "DoS":                0.95,
    "MITM":               0.98,
    "Replay":             0.75,
    "Spoofing":           0.80,
    "Data Falsification": 0.68,
}

# Static display metadata (color / level) — NOT used for the score anymore
ATTACK_META = {
    "Normal":             {"level": "Safe",     "color": "#00e5a0"},
    "DoS":                {"level": "Critical",  "color": "#ff2d55"},
    "MITM":               {"level": "Critical",  "color": "#ff2d55"},
    "Replay":             {"level": "High",      "color": "#ff9f0a"},
    "Spoofing":           {"level": "High",      "color": "#ff9f0a"},
    "Data Falsification": {"level": "Medium",    "color": "#ffd60a"},
}

def compute_dynamic_risk(proba_dict, predicted_attack):
    """
    Compute a 0-100 risk score dynamically from the model's probability vector.

    Method:
      1. Weighted-sum score  = Σ (prob[class] × severity_weight[class]) × 100
         This reflects the full distribution — even if the model is 60% sure
         it's DoS and 40% Replay, both contribute to the score.
      2. Confidence boost: amplify the score by the model's confidence in the
         predicted class so high-certainty dangerous predictions score higher
         than low-certainty ones of the same class.
      3. For Normal: invert so high confidence in Normal → low score.
      4. Clamp to [1, 99] and round.
    """
    # Step 1 — weighted sum across all classes
    weighted = sum(
        proba_dict.get(cls, 0.0) * ATTACK_SEVERITY_WEIGHTS[cls]
        for cls in ATTACK_SEVERITY_WEIGHTS
    )
    raw_score = weighted * 100  # 0-100 range

    # Step 2 — confidence of the predicted class
    confidence = proba_dict.get(predicted_attack, 0.5)

    if predicted_attack == "Normal":
        # High confidence in Normal = very low risk
        # Low confidence in Normal (model unsure) = slightly higher risk
        dynamic_score = raw_score + (1 - confidence) * 10
    else:
        # Scale up by confidence: certain dangerous prediction = higher score
        # Interpolate between raw_score and the class ceiling
        ceiling = ATTACK_SEVERITY_WEIGHTS[predicted_attack] * 100
        dynamic_score = raw_score + (ceiling - raw_score) * (confidence - 0.5) * 0.8

    return int(round(max(1, min(99, dynamic_score))))

def predict_attack(input_dict):
    """
    Run ML prediction and return:
      - attack name (str)
      - dynamic risk score (int 1-99)
      - per-class probability dict
      - confidence float
    """
    if ML_AVAILABLE:
        df = pd.DataFrame([input_dict])
        df_scaled = scaler.transform(df)

        pred_class = model.predict(df_scaled)[0]
        attack = attack_map[int(pred_class)]

        # Get probability vector (works for RF, SVM with prob=True, XGBoost, etc.)
        if hasattr(model, "predict_proba"):
            proba_raw = model.predict_proba(df_scaled)[0]
            # Map to class names using model.classes_
            classes = [attack_map[int(c)] for c in model.classes_]
            proba_dict = dict(zip(classes, [float(p) for p in proba_raw]))
        else:
            # Model doesn't support probabilities (e.g. LinearSVC)
            # Build a synthetic peaked distribution
            proba_dict = {cls: 0.02 for cls in attack_map.values()}
            proba_dict[attack] = 0.90
            leftover = 1.0 - 0.90 - 0.02 * (len(attack_map) - 1)
            for cls in proba_dict:
                if cls != attack:
                    proba_dict[cls] += leftover / (len(attack_map) - 1)

        confidence = proba_dict.get(attack, 0.5)
        dynamic_score = compute_dynamic_risk(proba_dict, attack)

    else:
        # ── Heuristic fallback (no model files) ──────────────────────────────
        packet_rate  = input_dict.get("packet_rate", 50)
        retrans      = input_dict.get("retransmission_rate", 0.01)
        entropy      = input_dict.get("payload_entropy", 3.5)
        resets       = input_dict.get("connection_reset_count", 0)
        flow_ratio   = input_dict.get("flow_direction_ratio", 1.0)
        byte_rate    = input_dict.get("byte_rate", 20000)

        if packet_rate > 200 or byte_rate > 100000:
            attack = "DoS"
            confidence = min(0.99, 0.70 + (packet_rate - 200) / 1000)
        elif resets > 5 or (retrans > 0.15 and flow_ratio > 2):
            attack = "MITM"
            confidence = min(0.99, 0.65 + resets * 0.03)
        elif retrans > 0.25:
            attack = "Replay"
            confidence = min(0.99, 0.60 + retrans)
        elif flow_ratio > 3.0:
            attack = "Spoofing"
            confidence = min(0.99, 0.60 + (flow_ratio - 3) * 0.1)
        elif entropy < 1.8:
            attack = "Data Falsification"
            confidence = min(0.99, 0.55 + (1.8 - entropy) * 0.2)
        else:
            attack = "Normal"
            confidence = 0.85

        # Build synthetic proba_dict
        proba_dict = {cls: (1 - confidence) / (len(attack_map) - 1) for cls in attack_map.values()}
        proba_dict[attack] = confidence

        dynamic_score = compute_dynamic_risk(proba_dict, attack)

    return attack, dynamic_score, proba_dict, confidence

recommendations = {
    "Normal": {
        "desc": "No anomaly detected. Device communication is operating within normal parameters.",
        "actions": ["Continue routine monitoring", "Schedule next security audit", "Keep firmware up to date"],
        "precautions": ["Maintain current security policies", "Log all access events", "Review access controls quarterly"]
    },
    "DoS": {
        "desc": "Denial of Service attack detected. Device may become unresponsive to legitimate requests.",
        "actions": ["Immediately isolate the device from the network", "Block suspicious IP ranges at firewall", "Notify security incident team", "Enable rate-limiting on the gateway"],
        "precautions": ["Implement traffic throttling", "Deploy intrusion detection system", "Set up automated DDoS mitigation", "Establish redundant communication paths"]
    },
    "MITM": {
        "desc": "Man-in-the-Middle attack detected. Data integrity and confidentiality are at risk.",
        "actions": ["Terminate current sessions immediately", "Rotate all authentication credentials", "Audit recent data transmissions", "Enable certificate pinning"],
        "precautions": ["Enforce TLS 1.3 for all communications", "Implement mutual authentication", "Use VPN tunnels for sensitive devices", "Monitor ARP tables regularly"]
    },
    "Replay": {
        "desc": "Replay attack detected. Captured packets are being retransmitted to impersonate legitimate devices.",
        "actions": ["Invalidate current session tokens", "Enable timestamp validation", "Check device authentication logs", "Force re-authentication of all sessions"],
        "precautions": ["Implement nonce-based authentication", "Use time-limited session tokens", "Enable sequence number verification", "Deploy packet inspection systems"]
    },
    "Spoofing": {
        "desc": "Spoofing attack detected. Malicious actor is impersonating a trusted device or address.",
        "actions": ["Verify device MAC and IP binding", "Revoke compromised device credentials", "Enable dynamic ARP inspection", "Alert connected systems of potential compromise"],
        "precautions": ["Implement strict device identity verification", "Use hardware security modules (HSM)", "Enable IP source guard", "Maintain trusted device registry"]
    },
    "Data Falsification": {
        "desc": "Data Falsification attack detected. Transmitted medical data may have been tampered with.",
        "actions": ["Halt data ingestion from this device", "Verify recent medical records integrity", "Cross-check readings with backup sensors", "Notify clinical staff immediately"],
        "precautions": ["Implement cryptographic data signing", "Use blockchain for audit trails", "Deploy anomaly detection on data values", "Establish data validation checksums"]
    }
}

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        users = load_json(USERS_FILE, {})
        name     = request.form.get("name","").strip()
        email    = request.form.get("email","").strip().lower()
        username = request.form.get("username","").strip()
        password = request.form.get("password","")

        if not all([name, email, username, password]):
            flash("All fields are required.", "error")
            return render_template("register.html")

        if username in users:
            flash("Username already exists.", "error")
            return render_template("register.html")

        if any(u["email"] == email for u in users.values()):
            flash("Email already registered.", "error")
            return render_template("register.html")

        user_id = str(uuid.uuid4())
        users[username] = {
            "id": user_id,
            "name": name,
            "email": email,
            "username": username,
            "password": hash_password(password),
            "created_at": datetime.now().isoformat()
        }
        save_json(USERS_FILE, users)
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        users = load_json(USERS_FILE, {})
        username = request.form.get("username","").strip()
        password = request.form.get("password","")

        user = users.get(username)
        if user and user["password"] == hash_password(password):
            session["user_id"]   = user["id"]
            session["username"]  = username
            session["name"]      = user["name"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    preds = load_json(PREDICTIONS_FILE, {})
    user_preds = [p for p in preds.values() if p["user_id"] == session["user_id"]]
    stats = {
        "total": len(user_preds),
        "critical": sum(1 for p in user_preds if ATTACK_META.get(p["attack"],{}).get("level") == "Critical"),
        "high": sum(1 for p in user_preds if ATTACK_META.get(p["attack"],{}).get("level") == "High"),
        "normal": sum(1 for p in user_preds if p["attack"] == "Normal"),
    }
    recent = sorted(user_preds, key=lambda x: x["timestamp"], reverse=True)[:5]
    return render_template("dashboard.html", stats=stats, recent=recent)

@app.route("/predict", methods=["GET","POST"])
def predict():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        data = request.json
        device_type_map = {
            "1": "ECG Monitor",
            "2": "Blood Pressure Monitor",
            "3": "Pulse Oximeter",
            "4": "Insulin Pump",
            "5": "Ventilator",
            "6": "Smart Infusion Pump"
        }
        input_data = {
            "flow_duration_ms":       float(data.get("flow_duration_ms", 3000)),
            "packet_rate":            float(data.get("packet_rate", 50)),
            "byte_rate":              float(data.get("byte_rate", 20000)),
            "avg_packet_size":        float(data.get("avg_packet_size", 400)),
            "packet_size_variance":   float(data.get("packet_size_variance", 1000)),
            "inter_arrival_time_mean":float(data.get("inter_arrival_time_mean", 20)),
            "inter_arrival_time_std": float(data.get("inter_arrival_time_std", 5)),
            "payload_entropy":        float(data.get("payload_entropy", 3.5)),
            "tcp_flag_count":         float(data.get("tcp_flag_count", 5)),
            "retransmission_rate":    float(data.get("retransmission_rate", 0.01)),
            "flow_direction_ratio":   float(data.get("flow_direction_ratio", 1.0)),
            "connection_reset_count": float(data.get("connection_reset_count", 0)),
            "session_request_rate":   float(data.get("session_request_rate", 5)),
            "device_type":            float(data.get("device_type", 2)),
        }

        attack, dynamic_score, proba_dict, confidence = predict_attack(input_data)

        meta  = ATTACK_META[attack]
        risk  = {
            "score": dynamic_score,
            "level": meta["level"],
            "color": meta["color"],
        }
        rec   = recommendations[attack]

        pred_id = str(uuid.uuid4())
        preds = load_json(PREDICTIONS_FILE, {})
        preds[pred_id] = {
            "id": pred_id,
            "user_id": session["user_id"],
            "username": session["username"],
            "device_name": device_type_map.get(str(int(input_data["device_type"])), "Unknown Device"),
            "input_data": input_data,
            "attack": attack,
            "risk_score": dynamic_score,
            "risk_level": meta["level"],
            "risk_color": meta["color"],
            "confidence": round(confidence * 100, 1),
            "proba_dict": proba_dict,
            "recommendations": rec,
            "timestamp": datetime.now().isoformat(),
            "ml_available": ML_AVAILABLE
        }
        save_json(PREDICTIONS_FILE, preds)

        return jsonify({
            "success": True,
            "pred_id": pred_id,
            "attack": attack,
            "risk": risk,
            "confidence": round(confidence * 100, 1),
            "proba_dict": proba_dict,
            "recommendations": rec
        })
    return render_template("predict.html")

@app.route("/history")
def history():
    if "user_id" not in session:
        return redirect(url_for("login"))
    preds = load_json(PREDICTIONS_FILE, {})
    user_preds = [p for p in preds.values() if p["user_id"] == session["user_id"]]
    user_preds = sorted(user_preds, key=lambda x: x["timestamp"], reverse=True)
    return render_template("history.html", predictions=user_preds)

@app.route("/history/<pred_id>")
def history_detail(pred_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    preds = load_json(PREDICTIONS_FILE, {})
    pred = preds.get(pred_id)
    if not pred or pred["user_id"] != session["user_id"]:
        flash("Prediction not found.", "error")
        return redirect(url_for("history"))
    return render_template("history_detail.html", pred=pred)

# ── Live Streaming ─────────────────────────────────────────────────────────────
import csv, io, threading, time as time_module

STREAM_SESSIONS = {}
STREAM_REPORTS_FILE = "stream_reports.json"

DEVICE_TYPE_MAP = {
    "1": "ECG Monitor", "2": "Blood Pressure Monitor",
    "3": "Pulse Oximeter", "4": "Insulin Pump",
    "5": "Ventilator", "6": "Smart Infusion Pump"
}

FEATURE_COLS = [
    "flow_duration_ms","packet_rate","byte_rate","avg_packet_size",
    "packet_size_variance","inter_arrival_time_mean","inter_arrival_time_std",
    "payload_entropy","tcp_flag_count","retransmission_rate",
    "flow_direction_ratio","connection_reset_count","session_request_rate","device_type"
]

@app.route("/stream")
def stream_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    reports = load_json(STREAM_REPORTS_FILE, {})
    user_reports = sorted(
        [r for r in reports.values() if r["user_id"] == session["user_id"]],
        key=lambda x: x["started_at"], reverse=True
    )
    return render_template("stream.html", reports=user_reports)

@app.route("/stream/upload", methods=["POST"])
def stream_upload():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    device = request.form.get("device_type", "2")
    interval = float(request.form.get("interval", 2))
    interval = max(0.5, min(60, interval))
    file = request.files.get("logfile")
    if not file:
        return jsonify({"success": False, "error": "No file uploaded"})
    try:
        content = file.read().decode("utf-8", errors="ignore")
        reader = csv.DictReader(io.StringIO(content))
        rows = []
        for row in reader:
            try:
                parsed = {}
                for col in FEATURE_COLS:
                    if col == "device_type":
                        parsed[col] = float(device)
                    else:
                        val = row.get(col, row.get(col.strip(), "0")) or "0"
                        parsed[col] = float(val)
                rows.append(parsed)
            except Exception:
                continue
        if not rows:
            return jsonify({"success": False, "error": "No valid rows found. Check column names match exactly."})
        stream_id = str(uuid.uuid4())
        STREAM_SESSIONS[stream_id] = {
            "stream_id": stream_id, "user_id": session["user_id"],
            "username": session["username"],
            "device_name": DEVICE_TYPE_MAP.get(str(device), "Unknown Device"),
            "device_type": device, "interval": interval,
            "rows": rows, "total": len(rows),
            "current_index": 0, "running": False, "stopped": False,
            "results": [], "started_at": None, "ended_at": None,
        }
        return jsonify({"success": True, "stream_id": stream_id, "total": len(rows)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/stream/start/<stream_id>", methods=["POST"])
def stream_start(stream_id):
    if "user_id" not in session:
        return jsonify({"success": False}), 401
    sess = STREAM_SESSIONS.get(stream_id)
    if not sess or sess["user_id"] != session["user_id"]:
        return jsonify({"success": False, "error": "Session not found"})
    if sess["running"]:
        return jsonify({"success": False, "error": "Already running"})
    sess["running"] = True
    sess["stopped"] = False
    sess["started_at"] = datetime.now().isoformat()
    sess["results"] = []
    sess["current_index"] = 0

    def run_stream():
        rows = sess["rows"]
        for i, row in enumerate(rows):
            if sess["stopped"]:
                break
            attack, score, proba_dict, confidence = predict_attack(row)
            meta = ATTACK_META[attack]
            sess["results"].append({
                "row": i + 1, "attack": attack, "score": score,
                "level": meta["level"], "color": meta["color"],
                "confidence": round(confidence * 100, 1),
                "proba_dict": proba_dict,
                "timestamp": datetime.now().isoformat(),
            })
            sess["current_index"] = i + 1
            if i < len(rows) - 1 and not sess["stopped"]:
                time_module.sleep(sess["interval"])  # read live each iteration
        sess["running"] = False
        sess["ended_at"] = datetime.now().isoformat()
        _save_stream_report(sess)

    threading.Thread(target=run_stream, daemon=True).start()
    return jsonify({"success": True})

@app.route("/stream/interval/<stream_id>", methods=["POST"])
def stream_update_interval(stream_id):
    if "user_id" not in session:
        return jsonify({"success": False}), 401
    sess = STREAM_SESSIONS.get(stream_id)
    if not sess or sess["user_id"] != session["user_id"]:
        return jsonify({"success": False, "error": "Session not found"})
    data = request.get_json()
    new_interval = float(data.get("interval", 2))
    new_interval = max(0.5, min(60, new_interval))
    sess["interval"] = new_interval          # background thread reads this live
    return jsonify({"success": True, "interval": new_interval})

@app.route("/stream/stop/<stream_id>", methods=["POST"])
def stream_stop(stream_id):
    if "user_id" not in session:
        return jsonify({"success": False}), 401
    sess = STREAM_SESSIONS.get(stream_id)
    if not sess:
        return jsonify({"success": False})
    sess["stopped"] = True
    sess["running"] = False
    sess["ended_at"] = datetime.now().isoformat()
    _save_stream_report(sess)
    return jsonify({"success": True})

@app.route("/stream/poll/<stream_id>")
def stream_poll(stream_id):
    if "user_id" not in session:
        return jsonify({"success": False}), 401
    sess = STREAM_SESSIONS.get(stream_id)
    if not sess:
        return jsonify({"success": False, "error": "Session not found"})
    from_idx = int(request.args.get("from", 0))
    new_results = sess["results"][from_idx:]
    return jsonify({
        "success": True, "running": sess["running"], "stopped": sess["stopped"],
        "current_index": sess["current_index"], "total": sess["total"],
        "new_results": new_results, "ended_at": sess.get("ended_at"),
    })

@app.route("/stream/report/<stream_id>")
def stream_report(stream_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    reports = load_json(STREAM_REPORTS_FILE, {})
    report = reports.get(stream_id)
    if not report or report["user_id"] != session["user_id"]:
        flash("Report not found.", "error")
        return redirect(url_for("stream_page"))
    return render_template("stream_report.html", report=report)

@app.route("/stream/report/<stream_id>/download")
def stream_report_download(stream_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    from flask import Response
    reports = load_json(STREAM_REPORTS_FILE, {})
    report = reports.get(stream_id)
    if not report or report["user_id"] != session["user_id"]:
        flash("Report not found.", "error")
        return redirect(url_for("stream_page"))
    lines = ["Row,Attack,Risk Score,Level,Confidence(%),Timestamp"]
    for r in report.get("results", []):
        lines.append(f"{r['row']},{r['attack']},{r['score']},{r['level']},{r['confidence']},{r['timestamp']}")
    csv_data = "\n".join(lines)
    return Response(csv_data, mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=stream_report_{stream_id[:8]}.csv"})

def _save_stream_report(sess):
    results = sess.get("results", [])
    if not results:
        return
    class_counts = {}
    for r in results:
        class_counts[r["attack"]] = class_counts.get(r["attack"], 0) + 1
    try:
        started = datetime.fromisoformat(sess["started_at"]) if sess["started_at"] else datetime.now()
        ended   = datetime.fromisoformat(sess["ended_at"])   if sess["ended_at"]   else datetime.now()
        elapsed = round((ended - started).total_seconds(), 1)
    except Exception:
        elapsed = 0
    anomalies = sum(v for k, v in class_counts.items() if k != "Normal")
    report = {
        "stream_id": sess["stream_id"], "user_id": sess["user_id"],
        "username": sess["username"], "device_name": sess["device_name"],
        "total_rows": sess["total"], "processed": len(results),
        "started_at": sess["started_at"], "ended_at": sess["ended_at"],
        "elapsed_sec": elapsed, "interval": sess["interval"],
        "class_counts": class_counts, "anomaly_count": anomalies,
        "results": results,
    }
    reports = load_json(STREAM_REPORTS_FILE, {})
    reports[sess["stream_id"]] = report
    save_json(STREAM_REPORTS_FILE, reports)
 
if __name__ == "__main__":
    app.run(debug=True, port=5000)