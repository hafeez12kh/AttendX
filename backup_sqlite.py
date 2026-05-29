import os
from sqlalchemy import create_engine, text

def backup_to_sqlite(db, models):
    # =========================
    # BASE DIRECTORY
    # =========================
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # =========================
    # BACKUP LOCATION
    # =========================
    backup_dir = os.path.join(base_dir, "Backup_Database")
    os.makedirs(backup_dir, exist_ok=True)

    sqlite_path = os.path.join(
        backup_dir,
        "attendance_backup.sqlite"
    )

    # =========================
    # SQLITE ENGINE
    # =========================
    sqlite_engine = create_engine(
        f"sqlite:///{sqlite_path}",
        connect_args={"check_same_thread": False}
    )

    # =========================
    # CREATE TABLES
    # =========================
    db.metadata.create_all(sqlite_engine)

    # =========================
    # 🔴 CLEAR EXISTING DATA (FIX)
    # =========================
    with sqlite_engine.begin() as conn:
        for model in models:
            table = model.__table__
            conn.execute(text(f"DELETE FROM {table.name}"))

    # =========================
    # COPY DATA (FRESH SNAPSHOT)
    # =========================
    for model in models:
        rows = db.session.query(model).all()
        if not rows:
            continue

        table = model.__table__

        with sqlite_engine.begin() as conn:
            for r in rows:
                conn.execute(
                    table.insert().values(
                        **{
                            c.name: getattr(r, c.name)
                            for c in table.columns
                        }
                    )
                )
