# ==============================
# 🔹 TEACHER / HOD FUNCTION
# ==============================

def get_subject_predictions(db, Attendance, Class, Student, teacher_id=None, class_id=None):

    results = []

    query = Class.query

    # ✅ Teacher filter
    if teacher_id:
        query = query.filter(Class.teacher_id == teacher_id)

    # ✅ Subject dropdown filter
    if class_id:
        query = query.filter(Class.id == int(class_id))


    classes = query.all()

    for cls in classes:

        cls_id = cls.id 
        subject_name = cls.name

        # ✅ Total sessions for this subject
        total_sessions = db.session.query(Attendance.session_id) \
            .filter(Attendance.class_id == cls_id) \
            .distinct() \
            .count()

        # ✅ Students in this subject
        students = db.session.query(Student.id, Student.roll) \
            .join(Attendance, Attendance.student_id == Student.id) \
            .filter(Attendance.class_id == cls_id) \
            .distinct() \
            .all()

# ✅ ADD THIS FIX
        if not students:
            continue
        
        for student_id, roll in students:

            attended_sessions = db.session.query(Attendance.session_id) \
                .filter(
                    Attendance.student_id == student_id,
                    Attendance.class_id == cls_id
                ) \
                .distinct() \
                .count()

            # ==============================
            # 🔥 CALCULATION LOGIC
            # ==============================
            print("CLASS:", subject_name, "STUDENTS:", len(students))
            if total_sessions == 0:
                current_percent = 0
                predicted_percent = 0
                worst_case = 0
          
            else:
                # ✅ Current %
                current_percent = (attended_sessions / total_sessions) * 100

                # 🔥 NEW PREDICTION (ADD HERE)
                predicted_percent = current_percent * 0.9

                # ✅ Worst-case
                future_classes = 5
                worst_case = (attended_sessions / (total_sessions + future_classes)) * 100

            # ==============================
            # 🔥 STATUS LOGIC
            # ==============================

            if current_percent >= 75:
                status = "Safe"
            elif current_percent >= 50:
                status = "Warning"
            else:
                status = "At Risk"

            # ==============================
            # 🔥 RESULT
            # ==============================

            results.append({
                "roll": roll,
                "subject": subject_name,
                "current": round(current_percent, 2),
                "predicted": round(predicted_percent, 2),
                "worst_case": round(worst_case, 2),
                "status": status
            })

    return results


# ==============================
# 🔹 STUDENT FUNCTION
# ==============================

def get_student_predictions(db, Attendance, Class, Student, student_id):

    if not student_id:
        print("❌ student_id missing from session")
        return []

    student = Student.query.filter_by(id=student_id).first()

    if not student:
        print("❌ student not found in DB:", student_id)
        return []

    results = []

    classes = db.session.query(Class.id, Class.name) \
        .join(Attendance, Attendance.class_id == Class.id) \
        .filter(Attendance.student_id == student.id) \
        .distinct() \
        .all()

    for class_id, subject_name in classes:

        total_sessions = db.session.query(Attendance.session_id) \
            .filter(Attendance.class_id == class_id) \
            .distinct() \
            .count()

        attended_sessions = db.session.query(Attendance.session_id) \
            .filter(
                Attendance.student_id == student.id,
                Attendance.class_id == class_id
            ) \
            .distinct() \
            .count()

        if total_sessions == 0:
            current_percent = 0
            predicted_percent = 0
            worst_case = 0
        else:
            current_percent = (attended_sessions / total_sessions) * 100
            predicted_percent = current_percent * 0.9
            worst_case = (attended_sessions / (total_sessions + 5)) * 100

        if current_percent >= 75:
            status = "Safe"
        elif current_percent >= 50:
            status = "Warning"
        else:
            status = "At Risk"

        results.append({
            "subject": subject_name,
            "current": round(current_percent, 2),
            "predicted": round(predicted_percent, 2),
            "worst_case": round(worst_case, 2),
            "status": status
        })

    return results
