from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
import firebase_admin
from firebase_admin import credentials, firestore, messaging
import uuid
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- Firebase setup ----------
cred = credentials.Certificate("firebase-service-account.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# ---------- Flask setup ----------
app = Flask(__name__)
app.secret_key = "super-secret-key-change-me"  # change in production!

# ---------- Helper utilities ----------
def current_student():
    if session.get("student_id"):
        return {
            "id": session["student_id"],
            "name": session["student_name"],
            "email": session["student_email"]
        }
    return None

def current_admin():
    if session.get("admin_id"):
        return {
            "id": session["admin_id"],
            "name": session["admin_name"],
            "email": session["admin_email"]
        }
    return None

def iso(dt):
    if not dt:
        return None
    try:
        return dt.isoformat() + "Z"
    except Exception:
        return str(dt)

def verify_and_migrate_password(doc_ref, stored_password, provided_password):
    """
    Verify stored_password against provided_password.
    If stored_password is plain text and matches, re-hash it in Firestore.
    Returns True if password valid, False otherwise.
    """
    if not stored_password:
        return False
    try:
        # If stored_password is a proper hash, this will work
        if check_password_hash(stored_password, provided_password):
            return True
    except ValueError:
        # This indicates stored_password was not a recognized hash format.
        # Fallback: compare plain text, and if matches, re-hash & update doc.
        if stored_password == provided_password:
            try:
                new_h = generate_password_hash(provided_password)
                doc_ref.update({"password": new_h})
                return True
            except Exception:
                return False
    return False

# ---------- Pages ----------
@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/home")
def home():
    return render_template("landing.html")

@app.route("/get-started")
def get_started():
    return render_template("get_started.html")

# ---------- Student auth ----------
@app.route("/student-signup", methods=["GET", "POST"])
def student_signup():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        # Only keep the fields we want
        department = request.form.get("department")
        phone = request.form.get("phone")

        existing = db.collection("students").where("email", "==", email).limit(1).stream()
        if any(existing):
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for("student_login"))

        student_id = str(uuid.uuid4())
        db.collection("students").document(student_id).set({
            "id": student_id,
            "name": name,
            "email": email,
            "password": generate_password_hash(password),
            "department": department,
            "phone": phone,
            "created_at": datetime.utcnow()
        })

        flash("Signup successful. Please login.", "success")
        return redirect(url_for("student_login"))
    return render_template("student_signup.html")

@app.route("/student-login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        docs = db.collection("students").where("email", "==", email).limit(1).stream()
        user_doc_snapshot = next(docs, None)
        if user_doc_snapshot:
            user_doc_ref = db.collection("students").document(user_doc_snapshot.id)
            data = user_doc_snapshot.to_dict()
            stored_password = data.get("password")
            if verify_and_migrate_password(user_doc_ref, stored_password, password):
                session["student_id"] = data["id"]
                session["student_name"] = data["name"]
                session["student_email"] = data["email"]
                flash(f"Welcome {data['name']}", "success")
                return redirect(url_for("student_dashboard"))

        flash("Invalid email or password", "danger")
        return redirect(url_for("student_login"))
    return render_template("student_login.html")

# Endpoint students (client) can call after obtaining FCM token client-side
@app.route("/api/register-token", methods=["POST"])
def api_register_token():
    s = current_student()
    if not s:
        return jsonify({"error": "not signed in"}), 403
    data = request.json or {}
    token = data.get("token")
    if not token:
        return jsonify({"error": "token required"}), 400
    db.collection("students").document(s["id"]).update({"fcm_token": token})
    return jsonify({"ok": True})

# ---------- Admin auth ----------
@app.route("/admin-signup", methods=["GET", "POST"])
def admin_signup():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        phone = request.form.get("phone", "").strip()
        role = request.form.get("role", "Faculty Admin")

        existing = db.collection("admins").where("email", "==", email).limit(1).stream()
        if any(existing):
            flash("Admin already registered. Please login.", "warning")
            return redirect(url_for("admin_login"))

        admin_id = str(uuid.uuid4())
        db.collection("admins").document(admin_id).set({
            "id": admin_id,
            "name": name,
            "email": email,
            "phone": phone,
            "role": role,
            "password": generate_password_hash(password),
            "created_at": datetime.utcnow()
        })

        flash("Admin registered, please login.", "success")
        return redirect(url_for("admin_login"))
    return render_template("admin_signup.html")

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        docs = db.collection("admins").where("email", "==", email).limit(1).stream()
        admin_doc_snapshot = next(docs, None)
        if admin_doc_snapshot:
            admin_ref = db.collection("admins").document(admin_doc_snapshot.id)
            data = admin_doc_snapshot.to_dict()
            stored_password = data.get("password")
            if verify_and_migrate_password(admin_ref, stored_password, password):
                session["admin_id"] = data["id"]
                session["admin_name"] = data["name"]
                session["admin_email"] = data["email"]
                flash(f"Welcome Admin {data['name']}", "success")
                return redirect(url_for("admin_dashboard"))

        flash("Invalid admin credentials", "danger")
        return redirect(url_for("admin_login"))
    return render_template("admin_login.html")

# ---------- Dashboards ----------
@app.route("/student-dashboard")
def student_dashboard():
    s = current_student()
    if not s:
        flash("Please login as student first", "warning")
        return redirect(url_for("student_login"))

    # fetch student's own reports sorted desc
    docs = db.collection("reports").where("reporter_id", "==", s["id"]).stream()
    reports = []
    for d in docs:
        doc = d.to_dict()
        doc["_created_raw"] = doc.get("created_at")
        reports.append(doc)

    reports.sort(key=lambda r: r.get("_created_raw") or datetime.min, reverse=True)
    for r in reports:
        r["created_at"] = iso(r.get("created_at"))
        # normalize replies => ensure list
        if r.get("replies") is None and r.get("reply") is not None:
            r["replies"] = [r.get("reply")]
        elif r.get("replies") is None:
            r["replies"] = []
        r.pop("_created_raw", None)

    return render_template("student_dashboard.html", student=s, reports=reports)

@app.route("/admin-dashboard")
def admin_dashboard():
    a = current_admin()
    if not a:
        flash("Please login as admin first", "warning")
        return redirect(url_for("admin_login"))
    return render_template("admin_dashboard.html", admin=a)

# ---------- Emergency Alerts (Admin → Students via FCM) ----------
@app.route("/send-alert", methods=["POST"])
def send_alert():
    a = current_admin()
    if not a:
        flash("Admin login required.", "danger")
        return redirect(url_for("admin_login"))

    title = request.form.get("title") or request.form.get("alert_title")
    message = request.form.get("message") or request.form.get("alert_body") or request.form.get("body")
    if not title or not message:
        flash("Title and message are required.", "warning")
        return redirect(url_for("admin_dashboard"))

    tokens = []
    for doc in db.collection("students").stream():
        d = doc.to_dict()
        t = d.get("fcm_token")
        if t:
            tokens.append(t)

    if not tokens:
        flash("No student devices are registered for alerts.", "warning")
        return redirect(url_for("admin_dashboard"))

    try:
        response = messaging.send_multicast(
            messaging.MulticastMessage(
                notification=messaging.Notification(title=title, body=message),
                tokens=tokens
            )
        )
    except Exception as e:
        alert_id = str(uuid.uuid4())
        db.collection("alerts").document(alert_id).set({
            "id": alert_id,
            "admin_id": a["id"],
            "admin_name": a["name"],
            "title": title,
            "body": message,
            "created_at": datetime.utcnow(),
            "success": 0,
            "failure": 0,
            "error": str(e)
        })
        flash(f"Failed to send alert: {e}", "danger")
        return redirect(url_for("admin_dashboard"))

    alert_id = str(uuid.uuid4())
    db.collection("alerts").document(alert_id).set({
        "id": alert_id,
        "admin_id": a["id"],
        "admin_name": a["name"],
        "title": title,
        "body": message,
        "created_at": datetime.utcnow(),
        "success": response.success_count,
        "failure": response.failure_count
    })

    flash(f"Alert sent: {response.success_count} success, {response.failure_count} failures.", "success")
    return redirect(url_for("admin_dashboard"))

# API for alerts (admin POST / GET) and students read-only GET
@app.route("/api/alerts", methods=["GET", "POST"])
def api_alerts():
    if request.method == "GET":
        # anyone logged in (student or admin) can read alerts
        docs = db.collection("alerts").order_by("created_at", direction=firestore.Query.DESCENDING).limit(200).stream()
        results = []
        for d in docs:
            alert = d.to_dict()
            alert["created_at"] = iso(alert.get("created_at"))
            results.append(alert)
        return jsonify(results)

    # POST: admin only
    a = current_admin()
    if not a:
        return jsonify({"error": "admin required"}), 403

    data = request.json or {}
    title = data.get("title")
    body = data.get("body") or data.get("message")
    if not title or not body:
        return jsonify({"error": "title and body required"}), 400

    tokens = [d.to_dict().get("fcm_token") for d in db.collection("students").stream() if d.to_dict().get("fcm_token")]
    alert_id = str(uuid.uuid4())
    alert_doc = {
        "id": alert_id,
        "admin_id": a["id"],
        "admin_name": a["name"],
        "title": title,
        "body": body,
        "created_at": datetime.utcnow(),
        "success": 0,
        "failure": 0
    }

    if tokens:
        try:
            response = messaging.send_multicast(
                messaging.MulticastMessage(
                    notification=messaging.Notification(title=title, body=body),
                    tokens=tokens
                )
            )
            alert_doc["success"] = response.success_count
            alert_doc["failure"] = response.failure_count
        except Exception as e:
            alert_doc["error"] = str(e)

    db.collection("alerts").document(alert_id).set(alert_doc)
    return jsonify({"ok": True, "alert_id": alert_id, "success": alert_doc.get("success", 0), "failure": alert_doc.get("failure", 0)})

# ---------- Reports ----------
@app.route("/api/reports", methods=["GET", "POST"])
def api_reports():
    # POST: create a new report (student)
    if request.method == "POST":
        s = current_student()
        if not s:
            return jsonify({"error": "student not logged in"}), 403

        data = request.get_json() or request.form
        # allow mood reports removed per request; everything here is incident reports or SOS

        location = data.get("location") or {}
        lat = None
        lng = None
        try:
            if location:
                lat = float(location.get("lat")) if location.get("lat") is not None else None
                lng = float(location.get("lng")) if location.get("lng") is not None else None
        except Exception:
            lat = None
            lng = None

        report_id = str(uuid.uuid4())
        report = {
            "id": report_id,
            "reporter_id": s["id"],
            "reporter_name": s["name"],
            "reporter_email": s["email"],
            "title": data.get("title", "Other"),
            "body": data.get("body", ""),
            "status": "Pending",
            "created_at": datetime.utcnow(),
            "location_text": data.get("location_text", "Unknown"),
            # store both lat/lng and a location object for frontends
            "lat": lat,
            "lng": lng,
            "location": {"lat": lat, "lng": lng} if lat is not None and lng is not None else None,
            "replies": []
        }

        db.collection("reports").document(report_id).set(report)
        return jsonify({"ok": True, "id": report_id})

    # GET: list reports (admin sees all, student sees own)
    a = current_admin()
    s = current_student()

    if a:
        docs = db.collection("reports").order_by("created_at", direction=firestore.Query.DESCENDING).stream()
    elif s:
        docs = db.collection("reports").where("reporter_id", "==", s["id"]).order_by("created_at", direction=firestore.Query.DESCENDING).stream()
    else:
        return jsonify({"error": "not logged in"}), 403

    results = []
    for d in docs:
        doc = d.to_dict()
        doc["created_at"] = iso(doc.get("created_at"))
        # ensure location object is present in returned JSON
        lat = doc.get("lat")
        lng = doc.get("lng")
        if lat is not None and lng is not None:
            doc["location"] = {"lat": lat, "lng": lng}
        else:
            doc["location"] = None
        # ensure replies list exists
        if "replies" not in doc or doc.get("replies") is None:
            # if older doc has 'reply', convert for response
            if doc.get("reply"):
                doc["replies"] = [doc.get("reply")]
            else:
                doc["replies"] = []
        results.append(doc)
    return jsonify(results)

@app.route("/api/reports/<report_id>/reply", methods=["POST"])
def api_reply_report(report_id):
    a = current_admin()
    if not a:
        return jsonify({"error": "admin only"}), 403

    data = request.json or {}
    text = data.get("text")
    if not text:
        return jsonify({"error": "reply text required"}), 400

    ref = db.collection("reports").document(report_id)
    if not ref.get().exists:
        return jsonify({"error": "report not found"}), 404

    reply = {
        "text": text,
        "admin_id": a["id"],
        "admin_name": a["name"],
        "created_at": datetime.utcnow()
    }

    # append to replies array and set status to 'responded'
    try:
        ref.update({
            "replies": firestore.ArrayUnion([reply]),
            "status": "Responded"
        })
    except Exception as e:
        return jsonify({"error": "failed to update report", "detail": str(e)}), 500

    return jsonify({"ok": True, "reply": reply})

# ---------- Appointment slots ----------
@app.route("/api/slots", methods=["GET", "POST"])
def api_slots():
    if request.method == "POST":
        a = current_admin()
        if not a:
            return jsonify({"error": "admin not logged in"}), 403

        data = request.json or {}
        start = data.get("start")
        end = data.get("end")
        department = data.get("department")

        # Normalize department to one of Clinic or Counseling
        if not department:
            return jsonify({"error": "department required"}), 400
        dep_norm = str(department).strip()
        dep_map = {
            "Clinic Department": "Clinic",
            "Clinic": "Clinic",
            "clinic": "Clinic",
            "Counseling Department": "Counseling",
            "Counseling": "Counseling",
            "counseling": "Counseling"
        }
        dep_norm = dep_map.get(dep_norm, dep_norm)
        if dep_norm not in ("Clinic", "Counseling"):
            return jsonify({"error": "department must be Clinic or Counseling"}), 400

        if not start or not end:
            return jsonify({"error": "start and end required"}), 400

        slot_id = str(uuid.uuid4())
        db.collection("slots").document(slot_id).set({
            "id": slot_id,
            "start": start,
            "end": end,
            "department": dep_norm,
            "created_by": a["id"],
            "created_by_name": a["name"],
            "booked_by": None,
            "student_name": None,
            "student_email": None,
            "created_at": datetime.utcnow()
        })
        return jsonify({"ok": True, "slot_id": slot_id})

    # GET
    dept = request.args.get("department")
    q = db.collection("slots")
    if dept:
        q = q.where("department", "==", dept)
    docs = q.order_by("start").stream()
    results = []
    for d in docs:
        doc = d.to_dict()
        doc["created_at"] = iso(doc.get("created_at"))
        results.append(doc)
    return jsonify(results)

@app.route("/api/slots/<slot_id>/book", methods=["POST"])
def api_book_slot(slot_id):
    s = current_student()
    if not s:
        return jsonify({"error": "student not logged in"}), 403

    slot_ref = db.collection("slots").document(slot_id)
    slot = slot_ref.get()
    if not slot.exists:
        return jsonify({"error": "slot not found"}), 404

    slot_data = slot.to_dict()
    if slot_data.get("booked_by"):
        return jsonify({"error": "Slot already booked"}), 400

    slot_ref.update({
        "booked_by": s["id"],
        "student_name": s["name"],
        "student_email": s["email"],
        "booked_at": datetime.utcnow()
    })
    # Return updated slot info for frontend sync
    slot_data.update({
        "booked_by": s["id"],
        "student_name": s["name"],
        "student_email": s["email"],
        "booked_at": iso(datetime.utcnow())
    })
    return jsonify({"ok": True, "slot": slot_data})

# ---------- Students listing for admin (department analytics) ----------
@app.route("/api/students", methods=["GET"])
def api_students():
    a = current_admin()
    if not a:
        return jsonify({"error": "admin only"}), 403
    docs = db.collection("students").stream()
    out = []
    for d in docs:
        s = d.to_dict()
        # return non-sensitive fields only
        out.append({
            "id": s.get("id"),
            "name": s.get("name"),
            "email": s.get("email"),
            "department": s.get("department")
        })
    return jsonify(out)

# ---------- Analytics ----------
@app.route("/api/analytics", methods=["GET"])
def api_analytics():
    a = current_admin()
    if not a:
        return jsonify({"error": "admin only"}), 403

    # Totals
    total_reports = len(list(db.collection("reports").stream()))
    total_alerts = len(list(db.collection("alerts").stream()))
    total_slots = len(list(db.collection("slots").stream()))
    total_students = len(list(db.collection("students").stream()))

    # Slots
    all_slots = [d.to_dict() for d in db.collection("slots").stream()]
    booked_slots = len([s for s in all_slots if s.get("booked_by")])

    # Reports by category
    reports = [d.to_dict() for d in db.collection("reports").stream()]
    report_categories = {}
    for r in reports:
        title = r.get("title", "Other")
        report_categories[title] = report_categories.get(title, 0) + 1

    # Slots booked trend by department (grouped by date)
    slot_trends = {}
    for s in all_slots:
        dept = s.get("department") or "Other"
        if s.get("booked_by"):
            # use date of booked_at if present, else created_at date
            booked_at = s.get("booked_at") or s.get("created_at")
            date = None
            if isinstance(booked_at, datetime):
                date = booked_at.date().isoformat()
            else:
                try:
                    date = str(booked_at).split("T")[0]
                except Exception:
                    date = "unknown"
            slot_trends.setdefault(dept, {})
            slot_trends[dept][date] = slot_trends[dept].get(date, 0) + 1

    # Students by department
    students = [d.to_dict() for d in db.collection("students").stream()]
    dept_distribution = {}
    for st in students:
        dept = st.get("department") or "Other"
        dept_distribution[dept] = dept_distribution.get(dept, 0) + 1

    return jsonify({
        "total_reports": total_reports,
        "total_alerts": total_alerts,
        "total_slots": total_slots,
        "total_students": total_students,
        "booked_slots": booked_slots,
        "report_categories": report_categories,
        "slot_trends": slot_trends,
        "dept_distribution": dept_distribution
    })

# ---------- Logout ----------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for("landing"))

if __name__ == "__main__":
    app.run(debug=True, port=5001)
