import pandas as pd
from sqlalchemy import func

def get_suspicion_scores(db, Attendance, Class, SessionDevice, Student, User,
                        teacher_id=None, role=None):

    query = db.session.query(
        Attendance.student_id,
        Student.roll,
        Class.name.label("class_name"),
        User.username.label("teacher_name"),
        Attendance.time,
        Attendance.date,
        Attendance.session_id,
        Attendance.class_id,
        Attendance.ip_address
    ).join(Student, Attendance.student_id == Student.id)\
     .join(Class, Attendance.class_id == Class.id)\
     .join(User, Class.teacher_id == User.id)

    if role == "teacher" and teacher_id:
        query = query.filter(Class.teacher_id == teacher_id)

    records = query.all()

    print("TOTAL RECORDS:", len(records))

    if not records:
        return []

    df = pd.DataFrame(records, columns=[
        "student_id", "roll", "class_name", "teacher_name",
        "time", "date", "session_id", "class_id", "ip"
    ])

    df["time_key"] = df["time"].apply(
        lambda t: t.hour * 60 + t.minute if t else 0
    )

    device_data = db.session.query(
        SessionDevice.student_id,
        func.count(func.distinct(SessionDevice.device_id))
    ).group_by(SessionDevice.student_id).all()

    device_map = {s: c for s, c in device_data}

    results = []

    for (roll, class_name, teacher_name), group in df.groupby(
        ["roll", "class_name", "teacher_name"]):

        total = len(group)

        if total < 5:
            results.append({
                "roll": roll,
                "class_name": class_name,
                "teacher_name": teacher_name,
                "score": 0,
                "status": "Insufficient Data",
                "reasons": "Not enough records"
            })
            continue

        score = 0
        reasons = []

        student_id = group["student_id"].iloc[0]

        # -------------------------------
        # REASON COUNTS
        # -------------------------------
        late_count = ((group["time_key"] - group["time_key"].min()) > 12).sum()

        pattern_count = group["time_key"].value_counts().max()

        device_count = device_map.get(student_id, 0)

        ip_count = group["ip"].nunique()


        # -------------------------------
        # APPLY LOGIC WITH COUNTS
        # -------------------------------

        # Late attendance
        if (late_count / total) > 0.6:
            score += 10
            reasons.append(f"Late attendance ({late_count})")

        # Same time pattern
        if (pattern_count / total) > 0.7:
            score += 25
            reasons.append(f"Same time pattern ({pattern_count})")

        # Multiple devices
        if device_count > 1:
            score += min((device_count - 1) * 5, 20)
            reasons.append(f"Multiple devices ({device_count - 1})")

        # IP changes
        if ip_count > 1:
            score += min((ip_count - 1) * 15, 40)
            reasons.append(f"IP changes ({ip_count})")

        if score >= 60:
            status = "High Risk"
        elif score >= 30:
            status = "Medium Risk"
        else:
            status = "Safe"

        results.append({
            "roll": roll,
            "class_name": class_name,
            "teacher_name": teacher_name,
            "score": score,
            "status": status,
            "reasons": ", ".join(reasons) if reasons else "Normal"
        })

    return sorted(results, key=lambda x: x["score"], reverse=True)