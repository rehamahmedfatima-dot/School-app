import os
import json
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# ============================
# التهيئة والإعدادات
# ============================
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 ساعة

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="مدرسة أحمد عبدالرحيم الثانوية", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================
# قاعدة البيانات (SQLite)
# ============================
DATABASE_URL = "sqlite:///./school.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ============================
# نماذج قاعدة البيانات (Models)
# ============================
class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)  # admin, teacher, student, parent
    avatar = Column(String, default="")

class Student(Base):
    __tablename__ = "students"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    national_id = Column(String, unique=True)
    parent = Column(String)
    class_id = Column(String, ForeignKey("classes.id"))
    medical = Column(String, default="")
    status = Column(String, default="نشطة")
    created_at = Column(DateTime, default=datetime.utcnow)

class Teacher(Base):
    __tablename__ = "teachers"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    subject = Column(String)
    salary = Column(Float, default=0)
    attendance = Column(String, default="حاضر")

class Class(Base):
    __tablename__ = "classes"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    section = Column(String)
    year = Column(String)
    capacity = Column(Integer, default=30)

class Attendance(Base):
    __tablename__ = "attendance"
    id = Column(String, primary_key=True, index=True)
    student_id = Column(String, ForeignKey("students.id"))
    date = Column(String, nullable=False)
    status = Column(String, nullable=False)  # حاضر, غائب, متأخر, عذر
    note = Column(String, default="")

class Exam(Base):
    __tablename__ = "exams"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    class_id = Column(String, ForeignKey("classes.id"))
    subject = Column(String)
    date = Column(String)

class Payment(Base):
    __tablename__ = "payments"
    id = Column(String, primary_key=True, index=True)
    student_id = Column(String, ForeignKey("students.id"))
    amount = Column(Float, nullable=False)
    type = Column(String, nullable=False)  # دخل, مصروف
    date = Column(String, nullable=False)
    status = Column(String, default="مدفوع")

class Book(Base):
    __tablename__ = "books"
    id = Column(String, primary_key=True, index=True)
    title = Column(String, nullable=False)
    author = Column(String)
    isbn = Column(String)
    status = Column(String, default="متاح")

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(String, primary_key=True, index=True)
    title = Column(String)
    message = Column(Text)
    role = Column(String)  # all, admin, teacher, student, parent
    date = Column(String)
    read = Column(Boolean, default=False)

# إنشاء الجداول
Base.metadata.create_all(bind=engine)

# ============================
# دوال مساعدة (Auth)
# ============================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

def get_current_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# ============================
# تهيئة بيانات تجريبية (Demo)
# ============================
def init_demo_data():
    db = SessionLocal()
    if db.query(User).count() == 0:
        demo_users = [
            {"id": "u1", "name": "أحمد المدير", "email": "admin@school.com", "password": "admin123", "role": "admin",
             "avatar": "أ"},
            {"id": "u2", "name": "نورة المعلمة", "email": "teacher@school.com", "password": "teacher123", "role": "teacher",
             "avatar": "ن"},
            {"id": "u3", "name": "سارة الطالبة", "email": "student@school.com", "password": "student123", "role": "student",
             "avatar": "س"},
            {"id": "u4", "name": "خالد ولي أمر", "email": "parent@school.com", "password": "parent123", "role": "parent",
             "avatar": "خ"},
        ]
        for u in demo_users:
            db.add(User(id=u["id"], name=u["name"], email=u["email"], hashed_password=get_password_hash(u["password"]),
                        role=u["role"], avatar=u["avatar"]))
        db.commit()

        # فصول
        classes = [
            {"id": "c1", "name": "الصف الأول", "section": "أ", "year": "2025-2026", "capacity": 30},
            {"id": "c2", "name": "الصف الثاني", "section": "ب", "year": "2025-2026", "capacity": 28},
            {"id": "c3", "name": "الصف الثالث", "section": "أ", "year": "2025-2026", "capacity": 25},
        ]
        for c in classes:
            db.add(Class(**c))
        db.commit()

        # طالبات
        students = [
            {"id": "s1", "name": "منى أحمد", "national_id": "123456789", "parent": "أحمد علي", "class_id": "c1",
             "medical": "لا يوجد", "status": "نشطة"},
            {"id": "s2", "name": "ليلى محمد", "national_id": "987654321", "parent": "محمد حسن", "class_id": "c2",
             "medical": "حساسية", "status": "نشطة"},
            {"id": "s3", "name": "نورا خالد", "national_id": "456789123", "parent": "خالد سعيد", "class_id": "c1",
             "medical": "", "status": "نشطة"},
        ]
        for s in students:
            db.add(Student(**s))
        db.commit()

        # معلمات
        teachers = [
            {"id": "t1", "name": "أماني عبدالله", "subject": "الرياضيات", "salary": 5000, "attendance": "حاضر"},
            {"id": "t2", "name": "ريم سليمان", "subject": "اللغة العربية", "salary": 4800, "attendance": "حاضر"},
        ]
        for t in teachers:
            db.add(Teacher(**t))
        db.commit()

        today = datetime.now().strftime("%Y-%m-%d")
        attendance = [
            {"id": "a1", "student_id": "s1", "date": today, "status": "حاضر", "note": ""},
            {"id": "a2", "student_id": "s2", "date": today, "status": "غائب", "note": "مرض"},
            {"id": "a3", "student_id": "s3", "date": today, "status": "حاضر", "note": ""},
        ]
        for a in attendance:
            db.add(Attendance(**a))
        db.commit()

        exams = [
            {"id": "e1", "name": "نصف العام", "class_id": "c1", "subject": "الرياضيات", "date": "2026-01-15"},
            {"id": "e2", "name": "نصف العام", "class_id": "c2", "subject": "اللغة العربية", "date": "2026-01-16"},
        ]
        for e in exams:
            db.add(Exam(**e))
        db.commit()

        payments = [
            {"id": "p1", "student_id": "s1", "amount": 500, "type": "دخل", "date": "2026-01-01", "status": "مدفوع"},
            {"id": "p2", "student_id": "s2", "amount": 300, "type": "دخل", "date": "2026-01-02", "status": "معلق"},
            {"id": "p3", "student_id": "s3", "amount": 200, "type": "مصروف", "date": "2026-01-03", "status": "مدفوع"},
        ]
        for p in payments:
            db.add(Payment(**p))
        db.commit()

        books = [
            {"id": "b1", "title": "الرياضيات المتقدمة", "author": "د. أحمد", "isbn": "978-3-16-148410-0", "status": "متاح"},
            {"id": "b2", "title": "النحو الواضح", "author": "علي الجارم", "isbn": "978-3-16-148411-7", "status": "مستعار"},
        ]
        for b in books:
            db.add(Book(**b))
        db.commit()
    db.close()

init_demo_data()

# ============================
# Pydantic Schemas (للاستقبال والإرسال)
# ============================
class UserLogin(BaseModel):
    email: str
    password: str
    role: str

class TokenData(BaseModel):
    access_token: str
    token_type: str
    user: dict

class StudentCreate(BaseModel):
    id: Optional[str] = None
    name: str
    national_id: str
    parent: Optional[str] = None
    class_id: str
    medical: Optional[str] = None
    status: str = "نشطة"

class TeacherCreate(BaseModel):
    id: Optional[str] = None
    name: str
    subject: str
    salary: float = 0
    attendance: str = "حاضر"

class ClassCreate(BaseModel):
    id: Optional[str] = None
    name: str
    section: Optional[str] = None
    year: str
    capacity: int = 30

class AttendanceCreate(BaseModel):
    id: Optional[str] = None
    student_id: str
    date: str
    status: str
    note: Optional[str] = None

class ExamCreate(BaseModel):
    id: Optional[str] = None
    name: str
    class_id: str
    subject: str
    date: str

class PaymentCreate(BaseModel):
    id: Optional[str] = None
    student_id: str
    amount: float
    type: str
    date: str
    status: str = "مدفوع"

class BookCreate(BaseModel):
    id: Optional[str] = None
    title: str
    author: str
    isbn: Optional[str] = None
    status: str = "متاح"

# ============================
# API Endpoints
# ============================

# ---- المصادقة ----
@app.post("/api/auth/login")
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_data.email).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="بيانات الدخول غير صحيحة")
    if user.role != user_data.role:
        raise HTTPException(status_code=401, detail="الدور غير مطابق")
    access_token = create_access_token(data={"sub": user.id})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role, "avatar": user.avatar}
    }

# ---- لوحة التحكم ----
@app.get("/api/dashboard")
def get_dashboard(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    students = db.query(Student).count()
    teachers = db.query(Teacher).count()
    classes = db.query(Class).count()
    today = datetime.now().strftime("%Y-%m-%d")
    today_att = db.query(Attendance).filter(Attendance.date == today).all()
    present = sum(1 for a in today_att if a.status == "حاضر")
    rate = round((present / len(today_att)) * 100) if today_att else 0
    return {
        "students": students,
        "teachers": teachers,
        "classes": classes,
        "attendance_rate": rate,
        "today_attendance": len(today_att)
    }

# ---- الطالبات ----
@app.get("/api/students")
def get_students(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Student).all()

@app.post("/api/students")
def create_student(data: StudentCreate, current_user: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    import uuid
    data.id = str(uuid.uuid4())[:8]
    student = Student(**data.dict())
    db.add(student)
    db.commit()
    db.refresh(student)
    return student

@app.put("/api/students/{student_id}")
def update_student(student_id: str, data: StudentCreate, current_user: User = Depends(get_current_admin),
                   db: Session = Depends(get_db)):
    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        raise HTTPException(404, "الطالبة غير موجودة")
    for key, value in data.dict().items():
        if key != "id":
            setattr(student, key, value)
    db.commit()
    return student

@app.delete("/api/students/{student_id}")
def delete_student(student_id: str, current_user: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        raise HTTPException(404, "الطالبة غير موجودة")
    db.delete(student)
    db.commit()
    return {"message": "تم الحذف"}

# ---- المعلمات ----
@app.get("/api/teachers")
def get_teachers(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Teacher).all()

@app.post("/api/teachers")
def create_teacher(data: TeacherCreate, current_user: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    import uuid
    data.id = str(uuid.uuid4())[:8]
    teacher = Teacher(**data.dict())
    db.add(teacher)
    db.commit()
    return teacher

@app.put("/api/teachers/{teacher_id}")
def update_teacher(teacher_id: str, data: TeacherCreate, current_user: User = Depends(get_current_admin),
                   db: Session = Depends(get_db)):
    teacher = db.query(Teacher).filter(Teacher.id == teacher_id).first()
    if not teacher:
        raise HTTPException(404, "المعلمة غير موجودة")
    for key, value in data.dict().items():
        if key != "id":
            setattr(teacher, key, value)
    db.commit()
    return teacher

@app.delete("/api/teachers/{teacher_id}")
def delete_teacher(teacher_id: str, current_user: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    teacher = db.query(Teacher).filter(Teacher.id == teacher_id).first()
    if not teacher:
        raise HTTPException(404, "المعلمة غير موجودة")
    db.delete(teacher)
    db.commit()
    return {"message": "تم الحذف"}

# ---- الفصول ----
@app.get("/api/classes")
def get_classes(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Class).all()

@app.post("/api/classes")
def create_class(data: ClassCreate, current_user: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    import uuid
    data.id = str(uuid.uuid4())[:8]
    cls = Class(**data.dict())
    db.add(cls)
    db.commit()
    return cls

@app.put("/api/classes/{class_id}")
def update_class(class_id: str, data: ClassCreate, current_user: User = Depends(get_current_admin),
                 db: Session = Depends(get_db)):
    cls = db.query(Class).filter(Class.id == class_id).first()
    if not cls:
        raise HTTPException(404, "الفصل غير موجود")
    for key, value in data.dict().items():
        if key != "id":
            setattr(cls, key, value)
    db.commit()
    return cls

@app.delete("/api/classes/{class_id}")
def delete_class(class_id: str, current_user: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    cls = db.query(Class).filter(Class.id == class_id).first()
    if not cls:
        raise HTTPException(404, "الفصل غير موجود")
    db.delete(cls)
    db.commit()
    return {"message": "تم الحذف"}

# ---- الحضور ----
@app.get("/api/attendance")
def get_attendance(date: Optional[str] = None, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(Attendance)
    if date:
        query = query.filter(Attendance.date == date)
    return query.all()

@app.post("/api/attendance")
def create_attendance(data: AttendanceCreate, current_user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    import uuid
    data.id = str(uuid.uuid4())[:8]
    att = Attendance(**data.dict())
    db.add(att)
    db.commit()
    return att

@app.delete("/api/attendance/{att_id}")
def delete_attendance(att_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    att = db.query(Attendance).filter(Attendance.id == att_id).first()
    if not att:
        raise HTTPException(404, "غير موجود")
    db.delete(att)
    db.commit()
    return {"message": "تم الحذف"}

# ---- الامتحانات ----
@app.get("/api/exams")
def get_exams(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Exam).all()

@app.post("/api/exams")
def create_exam(data: ExamCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    import uuid
    data.id = str(uuid.uuid4())[:8]
    exam = Exam(**data.dict())
    db.add(exam)
    db.commit()
    return exam

@app.delete("/api/exams/{exam_id}")
def delete_exam(exam_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    exam = db.query(Exam).filter(Exam.id == exam_id).first()
    if not exam:
        raise HTTPException(404, "غير موجود")
    db.delete(exam)
    db.commit()
    return {"message": "تم الحذف"}

# ---- المالية ----
@app.get("/api/payments")
def get_payments(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Payment).all()

@app.post("/api/payments")
def create_payment(data: PaymentCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    import uuid
    data.id = str(uuid.uuid4())[:8]
    payment = Payment(**data.dict())
    db.add(payment)
    db.commit()
    return payment

@app.delete("/api/payments/{payment_id}")
def delete_payment(payment_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    payment = db.query(Payment).filter(Payment.id == payment_id).first()
    if not payment:
        raise HTTPException(404, "غير موجود")
    db.delete(payment)
    db.commit()
    return {"message": "تم الحذف"}

# ---- المكتبة ----
@app.get("/api/books")
def get_books(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Book).all()

@app.post("/api/books")
def create_book(data: BookCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    import uuid
    data.id = str(uuid.uuid4())[:8]
    book = Book(**data.dict())
    db.add(book)
    db.commit()
    return book

@app.delete("/api/books/{book_id}")
def delete_book(book_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    book = db.query(Book).filter(Book.id == book_id).first()
    if not book:
        raise HTTPException(404, "غير موجود")
    db.delete(book)
    db.commit()
    return {"message": "تم الحذف"}

# ---- الذكاء الاصطناعي (تحليل حقيقي) ----
@app.get("/api/ai/insights")
def get_ai_insights(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    students = db.query(Student).all()
    today = datetime.now().strftime("%Y-%m-%d")
    # حساب الطالبات المعرضات للخطر بناءً على نسبة الغياب خلال آخر 30 يوم
    risk_students = []
    for s in students:
        # محاكاة تحليل بسيط: إذا كان لديها أكثر من غيابين مسجلين
        abs_count = db.query(Attendance).filter(
            Attendance.student_id == s.id,
            Attendance.status != "حاضر"
        ).count()
        if abs_count >= 2:
            risk_students.append(s.name)

    # نسبة الحضور اليوم
    today_att = db.query(Attendance).filter(Attendance.date == today).all()
    present = sum(1 for a in today_att if a.status == "حاضر")
    rate = round((present / len(today_att)) * 100) if today_att else 0

    return {
        "risk_count": len(risk_students),
        "risk_names": risk_students,
        "attendance_rate": rate,
        "message": f"هناك {len(risk_students)} طالبة معرضات لانخفاض المستوى بسبب كثرة الغياب."
    }

# ---- الإشعارات (نموذجية) ----
@app.get("/api/notifications")
def get_notifications(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Notification).all()

# ============================
# تقديم الواجهة الأمامية (HTML)
# ============================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدرسة أحمد عبدالرحيم الثانوية</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@300;400;500;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        /* --- نفس الـ CSS السابق مع تعديلات بسيطة --- */
        :root { --primary: #1a73e8; --primary-dark: #0d47a1; --primary-light: #e8f0fe; --secondary: #34a853; --secondary-light: #e6f4ea; --accent: #fbbc04; --danger: #ea4335; --danger-light: #fce8e6; --bg: #f5f7fa; --bg-card: #ffffff; --text: #202124; --text-secondary: #5f6368; --border: #dadce0; --shadow: 0 2px 12px rgba(0,0,0,0.08); --shadow-hover: 0 8px 30px rgba(0,0,0,0.12); --radius: 16px; --radius-sm: 10px; --transition: 0.3s cubic-bezier(0.4,0,0.2,1); --font: 'Tajawal', sans-serif; --sidebar-width: 260px; --header-height: 70px; --glass-bg: rgba(255,255,255,0.7); --glass-border: rgba(255,255,255,0.3); }
        [data-theme="dark"] { --bg: #1a1a2e; --bg-card: #16213e; --text: #e8eaed; --text-secondary: #9aa0a6; --border: #3a3a5c; --shadow: 0 2px 12px rgba(0,0,0,0.4); --shadow-hover: 0 8px 30px rgba(0,0,0,0.6); --glass-bg: rgba(22,33,62,0.8); --glass-border: rgba(255,255,255,0.05); --primary-light: #1a2a4a; --secondary-light: #1a3a2a; --danger-light: #3a1a1a; }
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:var(--font); background:var(--bg); color:var(--text); transition: background var(--transition), color var(--transition); min-height:100vh; overflow-x:hidden; }
        ::-webkit-scrollbar { width:6px; height:6px; }
        ::-webkit-scrollbar-track { background:var(--bg); }
        ::-webkit-scrollbar-thumb { background:var(--primary); border-radius:10px; }
        .hidden { display:none !important; }
        .flex { display:flex; } .flex-center { display:flex; align-items:center; justify-content:center; }
        .flex-between { display:flex; align-items:center; justify-content:space-between; }
        .gap-1 { gap:8px; } .gap-2 { gap:16px; } .gap-3 { gap:24px; }
        .wrap { flex-wrap:wrap; } .text-center { text-align:center; } .text-muted { color:var(--text-secondary); }
        .w-full { width:100%; } .mt-1 { margin-top:8px; } .mt-2 { margin-top:16px; } .mt-3 { margin-top:24px; }
        .mb-1 { margin-bottom:8px; } .mb-2 { margin-bottom:16px; } .mb-3 { margin-bottom:24px; }
        .btn { display:inline-flex; align-items:center; gap:8px; padding:10px 24px; border:none; border-radius:var(--radius-sm); font-family:var(--font); font-weight:600; font-size:14px; cursor:pointer; transition:var(--transition); text-decoration:none; background:var(--bg-card); color:var(--text); border:1px solid var(--border); }
        .btn-primary { background:var(--primary); color:#fff; border-color:var(--primary); }
        .btn-primary:hover { background:var(--primary-dark); transform:translateY(-2px); box-shadow:0 4px 16px rgba(26,115,232,0.3); }
        .btn-secondary { background:var(--secondary); color:#fff; border-color:var(--secondary); }
        .btn-danger { background:var(--danger); color:#fff; border-color:var(--danger); }
        .btn-outline { background:transparent; border:2px solid var(--primary); color:var(--primary); }
        .btn-sm { padding:6px 14px; font-size:12px; } .btn-lg { padding:14px 32px; font-size:16px; }
        #loginPage { min-height:100vh; display:flex; align-items:center; justify-content:center; background:linear-gradient(135deg, var(--primary) 0%, #0d47a1 100%); padding:20px; }
        .login-card { background:var(--bg-card); border-radius:var(--radius); padding:48px 40px; max-width:440px; width:100%; box-shadow:0 20px 60px rgba(0,0,0,0.3); }
        .login-card .logo { text-align:center; margin-bottom:32px; }
        .login-card .logo h1 { font-size:26px; font-weight:800; color:var(--primary); }
        .form-group { margin-bottom:18px; }
        .form-group label { display:block; font-weight:600; font-size:14px; margin-bottom:6px; color:var(--text); }
        .form-group input, .form-group select, .form-group textarea { width:100%; padding:12px 16px; border:2px solid var(--border); border-radius:var(--radius-sm); font-family:var(--font); font-size:14px; background:var(--bg); color:var(--text); transition:var(--transition); }
        .form-group input:focus, .form-group select:focus, .form-group textarea:focus { outline:none; border-color:var(--primary); box-shadow:0 0 0 4px rgba(26,115,232,0.15); }
        .form-row { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
        #appShell { display:none; min-height:100vh; }
        .app-header { position:fixed; top:0; left:0; right:0; height:var(--header-height); background:var(--glass-bg); backdrop-filter:blur(12px); border-bottom:1px solid var(--glass-border); display:flex; align-items:center; justify-content:space-between; padding:0 24px; z-index:1000; }
        .app-header .brand { display:flex; align-items:center; gap:12px; font-weight:800; font-size:18px; color:var(--primary); }
        .app-header .brand i { font-size:28px; }
        .app-sidebar { position:fixed; top:var(--header-height); left:0; bottom:0; width:var(--sidebar-width); background:var(--glass-bg); backdrop-filter:blur(12px); border-left:1px solid var(--glass-border); overflow-y:auto; padding:16px 12px; transition:transform var(--transition); z-index:999; }
        .app-sidebar .nav-item { display:flex; align-items:center; gap:14px; padding:12px 16px; border-radius:var(--radius-sm); cursor:pointer; transition:var(--transition); color:var(--text-secondary); font-weight:500; font-size:14px; margin-bottom:2px; }
        .app-sidebar .nav-item:hover { background:var(--primary-light); color:var(--primary); }
        .app-sidebar .nav-item.active { background:var(--primary); color:#fff; box-shadow:0 4px 12px rgba(26,115,232,0.3); }
        .app-sidebar .nav-item i { width:22px; text-align:center; }
        .app-sidebar .nav-section { font-size:11px; text-transform:uppercase; color:var(--text-secondary); padding:16px 16px 8px; font-weight:700; opacity:0.6; }
        .app-main { margin-right:var(--sidebar-width); margin-top:var(--header-height); padding:24px; min-height:calc(100vh - var(--header-height)); transition:margin-right var(--transition); }
        .page { display:none; animation:fadeIn 0.4s ease; }
        .page.active { display:block; }
        @keyframes fadeIn { from { opacity:0; transform:translateY(12px); } to { opacity:1; transform:translateY(0); } }
        .stat-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(200px,1fr)); gap:20px; margin-bottom:28px; }
        .stat-card { background:var(--bg-card); border-radius:var(--radius); padding:20px 24px; box-shadow:var(--shadow); border:1px solid var(--border); transition:var(--transition); }
        .stat-card:hover { transform:translateY(-4px); box-shadow:var(--shadow-hover); }
        .stat-card .stat-icon { width:48px; height:48px; border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:22px; margin-bottom:12px; }
        .stat-card .stat-icon.blue { background:var(--primary-light); color:var(--primary); }
        .stat-card .stat-icon.green { background:var(--secondary-light); color:var(--secondary); }
        .stat-card .stat-icon.orange { background:#fef3e0; color:#f9ab00; }
        .stat-card .stat-icon.red { background:var(--danger-light); color:var(--danger); }
        .stat-card .stat-number { font-size:28px; font-weight:800; }
        .stat-card .stat-label { color:var(--text-secondary); font-size:14px; font-weight:500; }
        .card { background:var(--bg-card); border-radius:var(--radius); padding:24px; box-shadow:var(--shadow); border:1px solid var(--border); margin-bottom:20px; }
        .card-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:16px; flex-wrap:wrap; gap:12px; }
        .card-title { font-size:18px; font-weight:700; }
        .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
        .grid-4 { display:grid; grid-template-columns:repeat(4,1fr); gap:20px; }
        .table-wrap { overflow-x:auto; }
        table { width:100%; border-collapse:collapse; font-size:14px; }
        table th { text-align:right; padding:12px 16px; background:var(--bg); font-weight:700; color:var(--text-secondary); border-bottom:2px solid var(--border); }
        table td { padding:12px 16px; border-bottom:1px solid var(--border); vertical-align:middle; }
        table tr:hover td { background:var(--primary-light); }
        .badge { display:inline-block; padding:4px 12px; border-radius:20px; font-size:12px; font-weight:600; }
        .badge-success { background:var(--secondary-light); color:var(--secondary); }
        .badge-danger { background:var(--danger-light); color:var(--danger); }
        .badge-warning { background:#fef3e0; color:#f9ab00; }
        .badge-info { background:var(--primary-light); color:var(--primary); }
        .ai-insight { background:linear-gradient(135deg, var(--primary-light), var(--secondary-light)); border-radius:var(--radius); padding:20px 24px; border-right:4px solid var(--primary); margin-bottom:16px; }
        .modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.5); backdrop-filter:blur(4px); z-index:2000; display:none; align-items:center; justify-content:center; padding:20px; }
        .modal-overlay.show { display:flex; }
        .modal-box { background:var(--bg-card); border-radius:var(--radius); max-width:640px; width:100%; max-height:90vh; overflow-y:auto; padding:32px; box-shadow:0 24px 80px rgba(0,0,0,0.3); animation:modalIn 0.3s ease; }
        @keyframes modalIn { from { opacity:0; transform:scale(0.95) translateY(20px); } to { opacity:1; transform:scale(1) translateY(0); } }
        .modal-box .modal-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:20px; }
        .modal-box .modal-close { background:none; border:none; font-size:28px; cursor:pointer; color:var(--text-secondary); }
        .modal-box .modal-close:hover { color:var(--danger); transform:rotate(90deg); }
        .sidebar-toggle { display:none; background:none; border:none; font-size:24px; cursor:pointer; color:var(--text); }
        @media (max-width:768px) { .app-sidebar { transform:translateX(100%); width:280px; } .app-sidebar.open { transform:translateX(0); } .app-main { margin-right:0; padding:16px; } .sidebar-toggle { display:block; } .grid-2, .grid-4 { grid-template-columns:1fr; } .form-row { grid-template-columns:1fr; } }
        .toast { position:fixed; bottom:24px; right:24px; background:var(--bg-card); border-radius:var(--radius-sm); padding:16px 24px; box-shadow:var(--shadow-hover); border-right:4px solid var(--primary); z-index:3000; display:none; align-items:center; gap:12px; animation:slideUp 0.4s ease; }
        .toast.show { display:flex; }
        @keyframes slideUp { from { opacity:0; transform:translateY(30px); } to { opacity:1; transform:translateY(0); } }
        .chart-container { position:relative; height:280px; }
        .empty-state { text-align:center; padding:40px 20px; color:var(--text-secondary); }
        .theme-toggle { background:none; border:none; font-size:20px; cursor:pointer; color:var(--text-secondary); padding:6px; border-radius:50%; }
        .user-badge { display:flex; align-items:center; gap:10px; padding:6px 14px 6px 18px; background:var(--primary-light); border-radius:30px; font-weight:600; font-size:14px; color:var(--primary); cursor:pointer; }
        .user-badge .avatar { width:32px; height:32px; border-radius:50%; background:var(--primary); color:#fff; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:14px; }
        .login-error { background:var(--danger-light); color:var(--danger); padding:10px 16px; border-radius:var(--radius-sm); display:none; margin-bottom:16px; }
    </style>
</head>
<body>
    <!-- Toast -->
    <div id="toast" class="toast"><i id="toastIcon" class="fas fa-check-circle"></i><span id="toastMessage">تم</span></div>

    <!-- Login -->
    <div id="loginPage">
        <div class="login-card">
            <div class="logo"><i class="fas fa-graduation-cap"></i><h1>مدرسة أحمد عبدالرحيم</h1><p>للبنات · نظام إدارة ذكي</p></div>
            <div id="loginError" class="login-error"><span id="loginErrorText">خطأ</span></div>
            <form id="loginForm" onsubmit="return handleLogin(event)">
                <div class="form-group"><label>البريد</label><input type="email" id="loginEmail" value="admin@school.com" required /></div>
                <div class="form-group"><label>كلمة المرور</label><input type="password" id="loginPassword" value="admin123" required /></div>
                <div class="form-group"><label>الدور</label>
                    <select id="loginRole"><option value="admin">مدير</option><option value="teacher">معلم</option><option value="student">طالبة</option><option value="parent">ولي أمر</option></select>
                </div>
                <button type="submit" class="btn btn-primary w-full btn-lg" style="justify-content:center;"><i class="fas fa-sign-in-alt"></i> دخول</button>
            </form>
        </div>
    </div>

    <!-- App -->
    <div id="appShell">
        <header class="app-header">
            <div class="flex" style="gap:12px;align-items:center;">
                <button class="sidebar-toggle" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
                <div class="brand"><i class="fas fa-graduation-cap"></i><span>مدرسة أحمد عبدالرحيم</span></div>
            </div>
            <div class="header-actions">
                <button class="theme-toggle" onclick="toggleTheme()"><i id="themeIcon" class="fas fa-moon"></i></button>
                <div class="user-badge" onclick="navigateTo('profile')"><div class="avatar" id="userAvatar">أ</div><span class="user-name" id="userName">المدير</span></div>
                <button class="btn btn-sm btn-danger" onclick="logout()"><i class="fas fa-sign-out-alt"></i></button>
            </div>
        </header>

        <nav class="app-sidebar" id="sidebar"><div id="sidebarNav"></div></nav>

        <main class="app-main" id="appMain">
            <!-- Dashboard -->
            <div class="page active" id="page-dashboard">
                <div class="flex-between wrap" style="margin-bottom:20px;">
                    <h2 style="font-size:24px;font-weight:800;"><i class="fas fa-chart-pie" style="color:var(--primary);"></i> لوحة التحكم</h2>
                    <span style="font-size:14px;color:var(--text-secondary);"><i class="far fa-calendar-alt"></i> <span id="currentDate"></span></span>
                </div>
                <div class="stat-grid" id="dashStats">
                    <div class="stat-card"><div class="stat-icon blue"><i class="fas fa-user-graduate"></i></div><div class="stat-number" id="statStudents">0</div><div class="stat-label">الطالبات</div></div>
                    <div class="stat-card"><div class="stat-icon green"><i class="fas fa-chalkboard-teacher"></i></div><div class="stat-number" id="statTeachers">0</div><div class="stat-label">المعلمات</div></div>
                    <div class="stat-card"><div class="stat-icon orange"><i class="fas fa-school"></i></div><div class="stat-number" id="statClasses">0</div><div class="stat-label">الفصول</div></div>
                    <div class="stat-card"><div class="stat-icon red"><i class="fas fa-user-check"></i></div><div class="stat-number" id="statAttendance">0%</div><div class="stat-label">نسبة الحضور</div></div>
                </div>
                <div class="grid-2">
                    <div class="card"><div class="card-header"><span class="card-title"><i class="fas fa-chart-bar" style="color:var(--primary);"></i> الحضور الأسبوعي</span></div><div class="chart-container"><canvas id="attendanceChart"></canvas></div></div>
                    <div class="card"><div class="card-header"><span class="card-title"><i class="fas fa-chart-line" style="color:var(--secondary);"></i> توزيع الطالبات</span></div><div class="chart-container"><canvas id="distributionChart"></canvas></div></div>
                </div>
                <div class="card" style="background:linear-gradient(135deg,var(--primary-light),var(--secondary-light));border:none;">
                    <div class="flex-between wrap">
                        <span style="font-weight:700;font-size:18px;"><i class="fas fa-robot" style="color:var(--primary);"></i> رؤى الذكاء الاصطناعي</span>
                        <button class="btn btn-sm btn-primary" onclick="generateAIInsights()"><i class="fas fa-sync-alt"></i> تحديث</button>
                    </div>
                    <div id="aiInsightsContainer" class="mt-2"></div>
                </div>
            </div>

            <!-- باقي الصفحات (Students, Teachers, Classes, Attendance, Exams, Finance, Library, Reports, Settings, Profile) -->
            <div class="page" id="page-students"><div class="flex-between wrap" style="margin-bottom:20px;"><h2 style="font-size:24px;font-weight:800;"><i class="fas fa-user-graduate" style="color:var(--primary);"></i> الطالبات</h2><button class="btn btn-primary" onclick="openStudentModal()"><i class="fas fa-plus"></i> تسجيل</button></div><div class="card"><div class="flex-between wrap mb-2"><input type="text" id="studentSearch" placeholder="بحث..." style="padding:8px 16px;border:2px solid var(--border);border-radius:var(--radius-sm);background:var(--bg);color:var(--text);width:220px;" oninput="renderStudents()" /><span id="studentCount">0</span></div><div class="table-wrap"><table><thead><tr><th>#</th><th>الاسم</th><th>المعرف</th><th>الفصل</th><th>ولي الأمر</th><th>الحالة</th><th>إجراءات</th></tr></thead><tbody id="studentTableBody"></tbody></table></div></div></div>
            <div class="page" id="page-teachers"><div class="flex-between wrap" style="margin-bottom:20px;"><h2 style="font-size:24px;font-weight:800;"><i class="fas fa-chalkboard-teacher" style="color:var(--primary);"></i> المعلمات</h2><button class="btn btn-primary" onclick="openTeacherModal()"><i class="fas fa-plus"></i> إضافة</button></div><div class="card"><div class="table-wrap"><table><thead><tr><th>#</th><th>الاسم</th><th>المادة</th><th>الراتب</th><th>الحضور</th><th>إجراءات</th></tr></thead><tbody id="teacherTableBody"></tbody></table></div></div></div>
            <div class="page" id="page-classes"><div class="flex-between wrap" style="margin-bottom:20px;"><h2 style="font-size:24px;font-weight:800;"><i class="fas fa-school" style="color:var(--primary);"></i> الفصول</h2><button class="btn btn-primary" onclick="openClassModal()"><i class="fas fa-plus"></i> إنشاء</button></div><div class="grid-2" id="classGrid"></div></div>
            <div class="page" id="page-attendance"><div class="flex-between wrap" style="margin-bottom:20px;"><h2 style="font-size:24px;font-weight:800;"><i class="fas fa-clipboard-check" style="color:var(--primary);"></i> الحضور</h2><button class="btn btn-primary" onclick="openAttendanceModal()"><i class="fas fa-plus"></i> تسجيل</button></div><div class="card"><input type="date" id="attendanceDate" onchange="renderAttendance()" style="padding:8px 16px;border:2px solid var(--border);border-radius:var(--radius-sm);margin-bottom:12px;" /><div class="table-wrap"><table><thead><tr><th>#</th><th>الطالبة</th><th>الفصل</th><th>التاريخ</th><th>الحالة</th><th>ملاحظات</th></tr></thead><tbody id="attendanceTableBody"></tbody></table></div></div></div>
            <div class="page" id="page-exams"><div class="flex-between wrap" style="margin-bottom:20px;"><h2 style="font-size:24px;font-weight:800;"><i class="fas fa-pencil-alt" style="color:var(--primary);"></i> الامتحانات</h2><button class="btn btn-primary" onclick="openExamModal()"><i class="fas fa-plus"></i> إضافة</button></div><div class="card"><div class="table-wrap"><table><thead><tr><th>#</th><th>الامتحان</th><th>الفصل</th><th>المادة</th><th>التاريخ</th><th>إجراءات</th></tr></thead><tbody id="examTableBody"></tbody></table></div></div></div>
            <div class="page" id="page-finance"><div class="flex-between wrap" style="margin-bottom:20px;"><h2 style="font-size:24px;font-weight:800;"><i class="fas fa-coins" style="color:var(--primary);"></i> المالية</h2><button class="btn btn-primary" onclick="openPaymentModal()"><i class="fas fa-plus"></i> دفعة</button></div><div class="stat-grid"><div class="stat-card"><div class="stat-number" id="finTotalIncome">0</div><div class="stat-label">الإيرادات</div></div><div class="stat-card"><div class="stat-number" id="finTotalExpenses">0</div><div class="stat-label">المصروفات</div></div><div class="stat-card"><div class="stat-number" id="finBalance">0</div><div class="stat-label">الرصيد</div></div></div><div class="card"><div class="table-wrap"><table><thead><tr><th>#</th><th>الطالبة</th><th>المبلغ</th><th>النوع</th><th>التاريخ</th><th>الحالة</th></tr></thead><tbody id="financeTableBody"></tbody></table></div></div></div>
            <div class="page" id="page-library"><div class="flex-between wrap" style="margin-bottom:20px;"><h2 style="font-size:24px;font-weight:800;"><i class="fas fa-book" style="color:var(--primary);"></i> المكتبة</h2><button class="btn btn-primary" onclick="openBookModal()"><i class="fas fa-plus"></i> كتاب</button></div><div class="card"><div class="table-wrap"><table><thead><tr><th>#</th><th>العنوان</th><th>المؤلف</th><th>الرقم الدولي</th><th>الحالة</th><th>إجراءات</th></tr></thead><tbody id="libraryTableBody"></tbody></table></div></div></div>
            <div class="page" id="page-reports"><h2 style="font-size:24px;font-weight:800;margin-bottom:20px;"><i class="fas fa-file-alt" style="color:var(--primary);"></i> التقارير</h2><div class="grid-2"><div class="card text-center" onclick="generateReport('attendance')" style="cursor:pointer;"><i class="fas fa-clipboard-check" style="font-size:40px;color:var(--primary);"></i><h4>الحضور</h4></div><div class="card text-center" onclick="generateReport('finance')" style="cursor:pointer;"><i class="fas fa-coins" style="font-size:40px;color:var(--secondary);"></i><h4>المالية</h4></div></div><div class="card" id="reportOutput"><div class="empty-state"><i class="fas fa-file-pdf"></i><h4>اختر تقريراً</h4></div></div></div>
            <div class="page" id="page-settings"><h2 style="font-size:24px;font-weight:800;margin-bottom:20px;"><i class="fas fa-cog" style="color:var(--primary);"></i> الإعدادات</h2><div class="grid-2"><div class="card"><h4>معلومات المدرسة</h4><div class="form-group"><label>الاسم</label><input type="text" id="schoolName" value="مدرسة أحمد عبدالرحيم" /></div><div class="form-group"><label>العام الدراسي</label><input type="text" id="academicYear" value="2025-2026" /></div><button class="btn btn-primary" onclick="saveSettings()"><i class="fas fa-save"></i> حفظ</button></div></div></div>
            <div class="page" id="page-profile"><h2 style="font-size:24px;font-weight:800;margin-bottom:20px;"><i class="fas fa-user-circle" style="color:var(--primary);"></i> الملف الشخصي</h2><div class="card"><div class="flex-center" style="flex-direction:column;gap:12px;"><div style="width:80px;height:80px;border-radius:50%;background:var(--primary);color:#fff;display:flex;align-items:center;justify-content:center;font-size:36px;font-weight:700;" id="profileAvatar">أ</div><h3 id="profileName">المدير</h3><p class="text-muted" id="profileRole">مدير</p></div><hr /><div class="form-group"><label>تغيير كلمة المرور</label><input type="password" id="newPassword" placeholder="كلمة جديدة" /></div><button class="btn btn-primary" onclick="changePassword()"><i class="fas fa-key"></i> تغيير</button></div></div>
        </main>
    </div>

    <!-- Modals (Student, Teacher, Class, Attendance, Exam, Payment, Book) -->
    <div class="modal-overlay" id="studentModal"><div class="modal-box"><div class="modal-header"><h3 id="studentModalTitle">تسجيل</h3><button class="modal-close" onclick="closeModal('studentModal')">&times;</button></div><form id="studentForm" onsubmit="return saveStudent(event)"><input type="hidden" id="studentEditId" /><div class="form-row"><div class="form-group"><label>الاسم</label><input type="text" id="sName" required /></div><div class="form-group"><label>المعرف</label><input type="text" id="sNationalId" required /></div></div><div class="form-row"><div class="form-group"><label>ولي الأمر</label><input type="text" id="sParent" /></div><div class="form-group"><label>الفصل</label><select id="sClass"></select></div></div><div class="form-group"><label>طبي</label><textarea id="sMedical"></textarea></div><div class="form-group"><label>الحالة</label><select id="sStatus"><option>نشطة</option><option>منقولة</option><option>مؤرشفة</option></select></div><button type="submit" class="btn btn-primary w-full"><i class="fas fa-save"></i> حفظ</button></form></div></div>
    <div class="modal-overlay" id="teacherModal"><div class="modal-box"><div class="modal-header"><h3 id="teacherModalTitle">إضافة</h3><button class="modal-close" onclick="closeModal('teacherModal')">&times;</button></div><form id="teacherForm" onsubmit="return saveTeacher(event)"><input type="hidden" id="teacherEditId" /><div class="form-row"><div class="form-group"><label>الاسم</label><input type="text" id="tName" required /></div><div class="form-group"><label>المادة</label><input type="text" id="tSubject" required /></div></div><div class="form-row"><div class="form-group"><label>الراتب</label><input type="number" id="tSalary" /></div><div class="form-group"><label>الحضور</label><select id="tAttendance"><option>حاضر</option><option>غائب</option></select></div></div><button type="submit" class="btn btn-primary w-full"><i class="fas fa-save"></i> حفظ</button></form></div></div>
    <div class="modal-overlay" id="classModal"><div class="modal-box"><div class="modal-header"><h3 id="classModalTitle">فصل</h3><button class="modal-close" onclick="closeModal('classModal')">&times;</button></div><form id="classForm" onsubmit="return saveClass(event)"><input type="hidden" id="classEditId" /><div class="form-row"><div class="form-group"><label>الاسم</label><input type="text" id="cName" required /></div><div class="form-group"><label>القسم</label><input type="text" id="cSection" /></div></div><div class="form-row"><div class="form-group"><label>السنة</label><input type="text" id="cYear" value="2025-2026" /></div><div class="form-group"><label>السعة</label><input type="number" id="cCapacity" value="30" /></div></div><button type="submit" class="btn btn-primary w-full"><i class="fas fa-save"></i> حفظ</button></form></div></div>
    <div class="modal-overlay" id="attendanceModal"><div class="modal-box"><div class="modal-header"><h3>تسجيل حضور</h3><button class="modal-close" onclick="closeModal('attendanceModal')">&times;</button></div><form id="attendanceForm" onsubmit="return saveAttendance(event)"><div class="form-group"><label>الطالبة</label><select id="attStudent" required></select></div><div class="form-row"><div class="form-group"><label>التاريخ</label><input type="date" id="attDate" required /></div><div class="form-group"><label>الحالة</label><select id="attStatus"><option>حاضر</option><option>غائب</option><option>متأخر</option><option>عذر</option></select></div></div><div class="form-group"><label>ملاحظات</label><textarea id="attNote"></textarea></div><button type="submit" class="btn btn-primary w-full"><i class="fas fa-save"></i> حفظ</button></form></div></div>
    <div class="modal-overlay" id="examModal"><div class="modal-box"><div class="modal-header"><h3 id="examModalTitle">امتحان</h3><button class="modal-close" onclick="closeModal('examModal')">&times;</button></div><form id="examForm" onsubmit="return saveExam(event)"><input type="hidden" id="examEditId" /><div class="form-group"><label>الاسم</label><input type="text" id="eName" required /></div><div class="form-row"><div class="form-group"><label>الفصل</label><select id="eClass" required></select></div><div class="form-group"><label>المادة</label><input type="text" id="eSubject" required /></div></div><div class="form-group"><label>التاريخ</label><input type="date" id="eDate" required /></div><button type="submit" class="btn btn-primary w-full"><i class="fas fa-save"></i> حفظ</button></form></div></div>
    <div class="modal-overlay" id="paymentModal"><div class="modal-box"><div class="modal-header"><h3>دفعة</h3><button class="modal-close" onclick="closeModal('paymentModal')">&times;</button></div><form id="paymentForm" onsubmit="return savePayment(event)"><div class="form-group"><label>الطالبة</label><select id="pStudent" required></select></div><div class="form-row"><div class="form-group"><label>المبلغ</label><input type="number" id="pAmount" required /></div><div class="form-group"><label>النوع</label><select id="pType"><option>دخل</option><option>مصروف</option></select></div></div><div class="form-group"><label>التاريخ</label><input type="date" id="pDate" required /></div><div class="form-group"><label>الحالة</label><select id="pStatus"><option>مدفوع</option><option>معلق</option></select></div><button type="submit" class="btn btn-primary w-full"><i class="fas fa-save"></i> حفظ</button></form></div></div>
    <div class="modal-overlay" id="bookModal"><div class="modal-box"><div class="modal-header"><h3 id="bookModalTitle">كتاب</h3><button class="modal-close" onclick="closeModal('bookModal')">&times;</button></div><form id="bookForm" onsubmit="return saveBook(event)"><input type="hidden" id="bookEditId" /><div class="form-group"><label>العنوان</label><input type="text" id="bTitle" required /></div><div class="form-row"><div class="form-group"><label>المؤلف</label><input type="text" id="bAuthor" required /></div><div class="form-group"><label>الرقم الدولي</label><input type="text" id="bIsbn" /></div></div><div class="form-group"><label>الحالة</label><select id="bStatus"><option>متاح</option><option>مستعار</option></select></div><button type="submit" class="btn btn-primary w-full"><i class="fas fa-save"></i> حفظ</button></form></div></div>

    <script>
        // ============================================================
        // جافا سكريبت متصل بالـ Backend (Fetch API)
        // ============================================================
        let currentUser = null;
        let currentPage = 'dashboard';
        let chartInstances = {};
        let API_BASE = window.location.origin + '/api';

        // دوال مساعدة
        function getToken() { return localStorage.getItem('sms_token'); }
        function setToken(t) { localStorage.setItem('sms_token', t); }
        function removeToken() { localStorage.removeItem('sms_token'); }
        function getHeaders() {
            return {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + getToken()
            };
        }

        async function fetchApi(endpoint, options = {}) {
            const res = await fetch(API_BASE + endpoint, {
                ...options,
                headers: { ...getHeaders(), ...(options.headers || {}) }
            });
            if (res.status === 401) {
                logout();
                throw new Error('Unauthorized');
            }
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'خطأ في الطلب');
            }
            return res.json();
        }

        function showToast(msg, type = 'success') {
            const el = document.getElementById('toast');
            const icon = document.getElementById('toastIcon');
            const msgEl = document.getElementById('toastMessage');
            msgEl.textContent = msg;
            el.className = 'toast show ' + type;
            icon.className = type === 'success' ? 'fas fa-check-circle' : 'fas fa-exclamation-circle';
            clearTimeout(el._timeout);
            el._timeout = setTimeout(() => el.classList.remove('show'), 3000);
        }

        // ============================================================
        // المصادقة
        // ============================================================
        async function handleLogin(e) {
            e.preventDefault();
            const email = document.getElementById('loginEmail').value.trim();
            const password = document.getElementById('loginPassword').value.trim();
            const role = document.getElementById('loginRole').value;
            try {
                const res = await fetch(API_BASE + '/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password, role })
                });
                if (!res.ok) {
                    const err = await res.json();
                    document.getElementById('loginError').style.display = 'block';
                    document.getElementById('loginErrorText').textContent = err.detail || 'خطأ في الدخول';
                    return false;
                }
                const data = await res.json();
                setToken(data.access_token);
                currentUser = data.user;
                document.getElementById('loginError').style.display = 'none';
                document.getElementById('loginPage').style.display = 'none';
                document.getElementById('appShell').style.display = 'block';
                initApp();
                showToast('مرحباً ' + currentUser.name);
            } catch (err) {
                document.getElementById('loginError').style.display = 'block';
                document.getElementById('loginErrorText').textContent = err.message || 'خطأ في الاتصال بالخادم';
            }
            return false;
        }

        function logout() {
            removeToken();
            currentUser = null;
            document.getElementById('loginPage').style.display = 'flex';
            document.getElementById('appShell').style.display = 'none';
            showToast('تم تسجيل الخروج');
        }

        // ============================================================
        // الوظائف الأساسية
        // ============================================================
        function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }

        function toggleTheme() {
            const html = document.documentElement;
            const dark = html.getAttribute('data-theme') === 'dark';
            html.setAttribute('data-theme', dark ? 'light' : 'dark');
            document.getElementById('themeIcon').className = dark ? 'fas fa-moon' : 'fas fa-sun';
            localStorage.setItem('sms_theme', dark ? 'light' : 'dark');
        }

        function closeModal(id) { document.getElementById(id).classList.remove('show'); }

        function openModal(id) { document.getElementById(id).classList.add('show'); }

        function getClassOptions() {
            return fetchApi('/classes').then(data => {
                return data.map(c => `<option value="${c.id}">${c.name}</option>`).join('');
            });
        }

        function getStudentOptions() {
            return fetchApi('/students').then(data => {
                return data.map(s => `<option value="${s.id}">${s.name}</option>`).join('');
            });
        }

        // ============================================================
        // التنقل
        // ============================================================
        function navigateTo(page) {
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            const target = document.getElementById('page-' + page);
            if (target) target.classList.add('active');
            currentPage = page;
            renderSidebar();
            if (page === 'dashboard') updateDashboard();
            if (page === 'students') renderStudents();
            if (page === 'teachers') renderTeachers();
            if (page === 'classes') renderClasses();
            if (page === 'attendance') renderAttendance();
            if (page === 'exams') renderExams();
            if (page === 'finance') renderFinance();
            if (page === 'library') renderLibrary();
            if (page === 'profile') updateProfile();
        }

        function renderSidebar() {
            const nav = document.getElementById('sidebarNav');
            const items = [
                { id: 'dashboard', icon: 'fa-chart-pie', label: 'لوحة التحكم' },
                { id: 'students', icon: 'fa-user-graduate', label: 'الطالبات' },
                { id: 'teachers', icon: 'fa-chalkboard-teacher', label: 'المعلمات' },
                { id: 'classes', icon: 'fa-school', label: 'الفصول' },
                { id: 'attendance', icon: 'fa-clipboard-check', label: 'الحضور' },
                { id: 'exams', icon: 'fa-pencil-alt', label: 'الامتحانات' },
                { id: 'finance', icon: 'fa-coins', label: 'المالية' },
                { id: 'library', icon: 'fa-book', label: 'المكتبة' },
                { id: 'reports', icon: 'fa-file-alt', label: 'التقارير' },
                { id: 'settings', icon: 'fa-cog', label: 'الإعدادات' },
                { id: 'profile', icon: 'fa-user-circle', label: 'الملف الشخصي' },
            ];
            let html = '';
            items.forEach((item, idx) => {
                if (idx === 0) html += `<div class="nav-section">الرئيسية</div>`;
                if (idx === 4) html += `<div class="nav-section">الإدارة</div>`;
                if (idx === 9) html += `<div class="nav-section">الحساب</div>`;
                const active = currentPage === item.id ? 'active' : '';
                html += `<div class="nav-item ${active}" onclick="navigateTo('${item.id}')">
                            <i class="fas ${item.icon}"></i> ${item.label}
                        </div>`;
            });
            nav.innerHTML = html;
        }

        // ============================================================
        // تحديث لوحة التحكم
        // ============================================================
        async function updateDashboard() {
            try {
                const data = await fetchApi('/dashboard');
                document.getElementById('statStudents').textContent = data.students;
                document.getElementById('statTeachers').textContent = data.teachers;
                document.getElementById('statClasses').textContent = data.classes;
                document.getElementById('statAttendance').textContent = data.attendance_rate + '%';
                document.getElementById('currentDate').textContent = new Date().toLocaleDateString('ar-EG', { year: 'numeric',
                    month: 'long', day: 'numeric' });
                // Charts
                const att = await fetchApi('/attendance');
                renderCharts(att);
                generateAIInsights();
            } catch (e) { console.error(e); }
        }

        function renderCharts(attendance) {
            const days = [];
            const presentData = [];
            const absentData = [];
            for (let i = 6; i >= 0; i--) {
                const d = new Date();
                d.setDate(d.getDate() - i);
                const ds = d.toISOString().split('T')[0];
                days.push(d.toLocaleDateString('ar-EG', { weekday: 'short' }));
                const dayAtt = attendance.filter(a => a.date === ds);
                const p = dayAtt.filter(a => a.status === 'حاضر').length;
                const a = dayAtt.filter(a => a.status !== 'حاضر').length;
                presentData.push(p);
                absentData.push(a);
            }
            const ctx1 = document.getElementById('attendanceChart').getContext('2d');
            if (chartInstances.attendance) chartInstances.attendance.destroy();
            chartInstances.attendance = new Chart(ctx1, {
                type: 'bar',
                data: {
                    labels: days,
                    datasets: [{ label: 'حاضر', data: presentData, backgroundColor: 'rgba(52,168,83,0.7)',
                            borderColor: '#34a853', borderWidth: 2 },
                        { label: 'غائب', data: absentData, backgroundColor: 'rgba(234,67,53,0.7)',
                            borderColor: '#ea4335', borderWidth: 2 }
                    ]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top' } },
                    scales: { y: { beginAtZero: true, stacked: true }, x: { stacked: true } } }
            });

            // Distribution
            fetchApi('/classes').then(classes => {
                fetchApi('/students').then(students => {
                    const labels = classes.map(c => c.name);
                    const counts = classes.map(c => students.filter(s => s.class_id === c.id).length);
                    const ctx2 = document.getElementById('distributionChart').getContext('2d');
                    if (chartInstances.distribution) chartInstances.distribution.destroy();
                    chartInstances.distribution = new Chart(ctx2, {
                        type: 'doughnut',
                        data: {
                            labels: labels.length ? labels : ['لا يوجد'],
                            datasets: [{ data: labels.length ? counts : [1], backgroundColor: ['#1a73e8',
                                    '#34a853', '#fbbc04', '#ea4335', '#9c27b0'
                                ] }]
                        },
                        options: { responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { position: 'bottom' } } }
                    });
                });
            });
        }

        // ============================================================
        // AI Insights (حقيقي)
        // ============================================================
        async function generateAIInsights() {
            try {
                const data = await fetchApi('/ai/insights');
                const container = document.getElementById('aiInsightsContainer');
                container.innerHTML = `
                            <div class="ai-insight"><i class="fas fa-lightbulb ai-icon"></i> <strong>توصية:</strong> ${data.message}</div>
                            <div class="ai-insight" style="border-right-color:var(--secondary);"><i class="fas fa-check-circle ai-icon" style="color:var(--secondary);"></i> <strong>نسبة الحضور:</strong> ${data.attendance_rate}%</div>
                            ${data.risk_names.length > 0 ? `<div class="ai-insight" style="border-right-color:var(--accent);"><i class="fas fa-user-graduate ai-icon" style="color:var(--accent);"></i> <strong>الطالبات المعرضات للخطر:</strong> ${data.risk_names.join('، ')}</div>` : ''}
                        `;
            } catch (e) { console.error(e); }
        }

        // ============================================================
        // الطالبات
        // ============================================================
        async function renderStudents() {
            try {
                const students = await fetchApi('/students');
                const classes = await fetchApi('/classes');
                document.getElementById('studentCount').textContent = students.length + ' طالبة';
                document.getElementById('sClass').innerHTML = '<option value="">اختر</option>' + classes.map(c =>
                    `<option value="${c.id}">${c.name}</option>`).join('');
                const tbody = document.getElementById('studentTableBody');
                if (!students.length) { tbody.innerHTML =
                        `<tr><td colspan="7" class="text-center">لا توجد طالبات</td></tr>`; return; }
                tbody.innerHTML = students.map((s, i) => {
                    const c = classes.find(cl => cl.id === s.class_id);
                    return `<tr><td>${i+1}</td><td><strong>${s.name}</strong></td><td>${s.national_id}</td><td>${c ? c.name : '-'}</td><td>${s.parent || '-'}</td><td><span class="badge ${s.status === 'نشطة' ? 'badge-success' : 'badge-warning'}">${s.status}</span></td>
                                <td><button class="btn btn-sm btn-primary" onclick="editStudent('${s.id}')"><i class="fas fa-edit"></i></button>
                                <button class="btn btn-sm btn-danger" onclick="deleteStudent('${s.id}')"><i class="fas fa-trash"></i></button></td></tr>`;
                }).join('');
            } catch (e) { console.error(e); }
        }

        async function openStudentModal(data) {
            document.getElementById('studentEditId').value = data ? data.id : '';
            document.getElementById('studentModalTitle').textContent = data ? 'تعديل' : 'تسجيل';
            document.getElementById('sName').value = data ? data.name : '';
            document.getElementById('sNationalId').value = data ? data.national_id : '';
            document.getElementById('sParent').value = data ? data.parent : '';
            document.getElementById('sClass').value = data ? data.class_id : '';
            document.getElementById('sMedical').value = data ? data.medical : '';
            document.getElementById('sStatus').value = data ? data.status : 'نشطة';
            openModal('studentModal');
        }

        async function editStudent(id) {
            const students = await fetchApi('/students');
            const s = students.find(x => x.id === id);
            if (s) openStudentModal(s);
        }

        async function deleteStudent(id) {
            if (!confirm('حذف؟')) return;
            await fetchApi('/students/' + id, { method: 'DELETE' });
            renderStudents();
            updateDashboard();
            showToast('تم الحذف');
        }

        async function saveStudent(e) {
            e.preventDefault();
            const id = document.getElementById('studentEditId').value;
            const data = {
                name: document.getElementById('sName').value.trim(),
                national_id: document.getElementById('sNationalId').value.trim(),
                parent: document.getElementById('sParent').value.trim(),
                class_id: document.getElementById('sClass').value,
                medical: document.getElementById('sMedical').value.trim(),
                status: document.getElementById('sStatus').value,
            };
            if (!data.name) { showToast('أدخل الاسم', 'error'); return false; }
            try {
                if (id) {
                    await fetchApi('/students/' + id, { method: 'PUT', body: JSON.stringify(data) });
                } else {
                    await fetchApi('/students', { method: 'POST', body: JSON.stringify(data) });
                }
                closeModal('studentModal');
                renderStudents();
                updateDashboard();
                showToast(id ? 'تم التحديث' : 'تم التسجيل');
            } catch (err) { showToast(err.message, 'error'); }
            return false;
        }

        // ============================================================
        // المعلمات (بنفس النمط، مختصر للطول)
        // ============================================================
        async function renderTeachers() {
            try {
                const teachers = await fetchApi('/teachers');
                const tbody = document.getElementById('teacherTableBody');
                if (!teachers.length) { tbody.innerHTML =
                        `<tr><td colspan="6" class="text-center">لا توجد معلمات</td></tr>`; return; }
                tbody.innerHTML = teachers.map((t, i) =>
                    `<tr><td>${i+1}</td><td><strong>${t.name}</strong></td><td>${t.subject}</td><td>${t.salary} ج.م</td><td><span class="badge ${t.attendance === 'حاضر' ? 'badge-success' : 'badge-danger'}">${t.attendance}</span></td>
                                <td><button class="btn btn-sm btn-primary" onclick="editTeacher('${t.id}')"><i class="fas fa-edit"></i></button>
                                <button class="btn btn-sm btn-danger" onclick="deleteTeacher('${t.id}')"><i class="fas fa-trash"></i></button></td></tr>`
                ).join('');
            } catch (e) { console.error(e); }
        }

        async function openTeacherModal(data) {
            document.getElementById('teacherEditId').value = data ? data.id : '';
            document.getElementById('teacherModalTitle').textContent = data ? 'تعديل' : 'إضافة';
            document.getElementById('tName').value = data ? data.name : '';
            document.getElementById('tSubject').value = data ? data.subject : '';
            document.getElementById('tSalary').value = data ? data.salary : '';
            document.getElementById('tAttendance').value = data ? data.attendance : 'حاضر';
            openModal('teacherModal');
        }

        async function editTeacher(id) { const teachers = await fetchApi('/teachers'); const t = teachers.find(x => x.id ===
                id); if (t) openTeacherModal(t); }

        async function deleteTeacher(id) { if (!confirm('حذف؟')) return; await fetchApi('/teachers/' + id, { method: 'DELETE' });
            renderTeachers();
            updateDashboard();
            showToast('تم الحذف'); }

        async function saveTeacher(e) {
            e.preventDefault();
            const id = document.getElementById('teacherEditId').value;
            const data = {
                name: document.getElementById('tName').value.trim(),
                subject: document.getElementById('tSubject').value.trim(),
                salary: parseFloat(document.getElementById('tSalary').value) || 0,
                attendance: document.getElementById('tAttendance').value,
            };
            if (!data.name) { showToast('أدخل الاسم', 'error'); return false; }
            try {
                if (id) await fetchApi('/teachers/' + id, { method: 'PUT', body: JSON.stringify(data) });
                else await fetchApi('/teachers', { method: 'POST', body: JSON.stringify(data) });
                closeModal('teacherModal');
                renderTeachers();
                updateDashboard();
                showToast(id ? 'تم التحديث' : 'تم الإضافة');
            } catch (err) { showToast(err.message, 'error'); }
            return false;
        }

        // ============================================================
        // باقي الوحدات (Classes, Attendance, Exams, Finance, Library) - مختصرة بنفس المنطق
        // ============================================================
        async function renderClasses() {
            try {
                const classes = await fetchApi('/classes');
                const students = await fetchApi('/students');
                const grid = document.getElementById('classGrid');
                if (!classes.length) { grid.innerHTML =
                        `<div class="card empty-state"><i class="fas fa-school"></i><h4>لا توجد فصول</h4></div>`; return; }
                grid.innerHTML = classes.map(c => {
                    const count = students.filter(s => s.class_id === c.id).length;
                    return `<div class="card" style="border-right:4px solid var(--primary);">
                                <div class="flex-between"><h4>${c.name}</h4><span class="badge badge-info">${c.section||'أ'}</span></div>
                                <p class="text-muted">${c.year}</p>
                                <p><i class="fas fa-user-graduate"></i> ${count} / ${c.capacity} طالبة</p>
                                <div class="flex gap-1 mt-2">
                                    <button class="btn btn-sm btn-primary" onclick="editClass('${c.id}')"><i class="fas fa-edit"></i></button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteClass('${c.id}')"><i class="fas fa-trash"></i></button>
                                </div>
                            </div>`;
                }).join('');
            } catch (e) { console.error(e); }
        }

        async function openClassModal(data) {
            document.getElementById('classEditId').value = data ? data.id : '';
            document.getElementById('classModalTitle').textContent = data ? 'تعديل' : 'إنشاء';
            document.getElementById('cName').value = data ? data.name : '';
            document.getElementById('cSection').value = data ? data.section : '';
            document.getElementById('cYear').value = data ? data.year : '2025-2026';
            document.getElementById('cCapacity').value = data ? data.capacity : 30;
            openModal('classModal');
        }

        async function editClass(id) { const classes = await fetchApi('/classes'); const c = classes.find(x => x.id === id); if (
                c) openClassModal(c); }

        async function deleteClass(id) { if (!confirm('حذف؟')) return; await fetchApi('/classes/' + id, { method: 'DELETE' });
            renderClasses();
            updateDashboard();
            showToast('تم الحذف'); }

        async function saveClass(e) {
            e.preventDefault();
            const id = document.getElementById('classEditId').value;
            const data = {
                name: document.getElementById('cName').value.trim(),
                section: document.getElementById('cSection').value.trim(),
                year: document.getElementById('cYear').value.trim(),
                capacity: parseInt(document.getElementById('cCapacity').value) || 30,
            };
            if (!data.name) { showToast('أدخل الاسم', 'error'); return false; }
            try {
                if (id) await fetchApi('/classes/' + id, { method: 'PUT', body: JSON.stringify(data) });
                else await fetchApi('/classes', { method: 'POST', body: JSON.stringify(data) });
                closeModal('classModal');
                renderClasses();
                updateDashboard();
                showToast(id ? 'تم التحديث' : 'تم الإنشاء');
            } catch (err) { showToast(err.message, 'error'); }
            return false;
        }

        // Attendance
        async function renderAttendance() {
            try {
                const date = document.getElementById('attendanceDate').value || new Date().toISOString().split('T')[0];
                document.getElementById('attendanceDate').value = date;
                const att = await fetchApi('/attendance?date=' + date);
                const students = await fetchApi('/students');
                const classes = await fetchApi('/classes');
                const tbody = document.getElementById('attendanceTableBody');
                if (!att.length) { tbody.innerHTML =
                        `<tr><td colspan="6" class="text-center">لا توجد سجلات</td></tr>`; return; }
                tbody.innerHTML = att.map((a, i) => {
                    const s = students.find(x => x.id === a.student_id);
                    const c = classes.find(x => x.id === (s ? s.class_id : null));
                    return `<tr><td>${i+1}</td><td>${s ? s.name : a.student_id}</td><td>${c ? c.name : '-'}</td><td>${a.date}</td>
                                <td><span class="badge ${a.status === 'حاضر' ? 'badge-success' : a.status === 'غائب' ? 'badge-danger' : 'badge-warning'}">${a.status}</span></td>
                                <td>${a.note || '-'}</td></tr>`;
                }).join('');
                document.getElementById('attStudent').innerHTML = '<option value="">اختر</option>' + students.map(s =>
                    `<option value="${s.id}">${s.name}</option>`).join('');
            } catch (e) { console.error(e); }
        }

        async function saveAttendance(e) {
            e.preventDefault();
            const data = {
                student_id: document.getElementById('attStudent').value,
                date: document.getElementById('attDate').value,
                status: document.getElementById('attStatus').value,
                note: document.getElementById('attNote').value.trim(),
            };
            if (!data.student_id) { showToast('اختر طالبة', 'error'); return false; }
            try {
                await fetchApi('/attendance', { method: 'POST', body: JSON.stringify(data) });
                closeModal('attendanceModal');
                renderAttendance();
                updateDashboard();
                showToast('تم التسجيل');
            } catch (err) { showToast(err.message, 'error'); }
            return false;
        }

        // Exams (مختصر)
        async function renderExams() {
            try {
                const exams = await fetchApi('/exams');
                const classes = await fetchApi('/classes');
                const tbody = document.getElementById('examTableBody');
                if (!exams.length) { tbody.innerHTML =
                        `<tr><td colspan="6" class="text-center">لا توجد امتحانات</td></tr>`; return; }
                tbody.innerHTML = exams.map((e, i) => {
                    const c = classes.find(x => x.id === e.class_id);
                    return `<tr><td>${i+1}</td><td><strong>${e.name}</strong></td><td>${c ? c.name : '-'}</td><td>${e.subject}</td><td>${e.date}</td>
                                <td><button class="btn btn-sm btn-danger" onclick="deleteExam('${e.id}')"><i class="fas fa-trash"></i></button></td></tr>`;
                }).join('');
                document.getElementById('eClass').innerHTML = '<option value="">اختر</option>' + classes.map(c =>
                    `<option value="${c.id}">${c.name}</option>`).join('');
            } catch (e) { console.error(e); }
        }

        async function deleteExam(id) { if (!confirm('حذف؟')) return; await fetchApi('/exams/' + id, { method: 'DELETE' });
            renderExams();
            showToast('تم الحذف'); }

        async function saveExam(e) {
            e.preventDefault();
            const data = {
                name: document.getElementById('eName').value.trim(),
                class_id: document.getElementById('eClass').value,
                subject: document.getElementById('eSubject').value.trim(),
                date: document.getElementById('eDate').value,
            };
            if (!data.name) { showToast('أدخل الاسم', 'error'); return false; }
            try {
                await fetchApi('/exams', { method: 'POST', body: JSON.stringify(data) });
                closeModal('examModal');
                renderExams();
                showToast('تم الإضافة');
            } catch (err) { showToast(err.message, 'error'); }
            return false;
        }

        // Finance
        async function renderFinance() {
            try {
                const payments = await fetchApi('/payments');
                const students = await fetchApi('/students');
                const tbody = document.getElementById('financeTableBody');
                if (!payments.length) { tbody.innerHTML =
                        `<tr><td colspan="6" class="text-center">لا توجد معاملات</td></tr>`; return; }
                const income = payments.filter(p => p.type === 'دخل').reduce((s, p) => s + p.amount, 0);
                const expenses = payments.filter(p => p.type === 'مصروف').reduce((s, p) => s + p.amount, 0);
                document.getElementById('finTotalIncome').textContent = income + ' ج.م';
                document.getElementById('finTotalExpenses').textContent = expenses + ' ج.م';
                document.getElementById('finBalance').textContent = (income - expenses) + ' ج.م';
                tbody.innerHTML = payments.map((p, i) => {
                    const s = students.find(x => x.id === p.student_id);
                    return `<tr><td>${i+1}</td><td>${s ? s.name : '-'}</td><td><strong>${p.amount}</strong></td>
                                <td><span class="badge ${p.type === 'دخل' ? 'badge-success' : 'badge-danger'}">${p.type}</span></td>
                                <td>${p.date}</td><td><span class="badge ${p.status === 'مدفوع' ? 'badge-success' : 'badge-warning'}">${p.status}</span></td></tr>`;
                }).join('');
                document.getElementById('pStudent').innerHTML = '<option value="">اختر</option>' + students.map(s =>
                    `<option value="${s.id}">${s.name}</option>`).join('');
            } catch (e) { console.error(e); }
        }

        async function savePayment(e) {
            e.preventDefault();
            const data = {
                student_id: document.getElementById('pStudent').value,
                amount: parseFloat(document.getElementById('pAmount').value) || 0,
                type: document.getElementById('pType').value,
                date: document.getElementById('pDate').value,
                status: document.getElementById('pStatus').value,
            };
            if (!data.student_id) { showToast('اختر طالبة', 'error'); return false; }
            try {
                await fetchApi('/payments', { method: 'POST', body: JSON.stringify(data) });
                closeModal('paymentModal');
                renderFinance();
                updateDashboard();
                showToast('تم التسجيل');
            } catch (err) { showToast(err.message, 'error'); }
            return false;
        }

        // Library
        async function renderLibrary() {
            try {
                const books = await fetchApi('/books');
                const tbody = document.getElementById('libraryTableBody');
                if (!books.length) { tbody.innerHTML =
                        `<tr><td colspan="6" class="text-center">لا توجد كتب</td></tr>`; return; }
                tbody.innerHTML = books.map((b, i) =>
                    `<tr><td>${i+1}</td><td><strong>${b.title}</strong></td><td>${b.author}</td><td>${b.isbn || '-'}</td>
                                <td><span class="badge ${b.status === 'متاح' ? 'badge-success' : 'badge-warning'}">${b.status}</span></td>
                                <td><button class="btn btn-sm btn-danger" onclick="deleteBook('${b.id}')"><i class="fas fa-trash"></i></button></td></tr>`
                ).join('');
            } catch (e) { console.error(e); }
        }

        async function deleteBook(id) { if (!confirm('حذف؟')) return; await fetchApi('/books/' + id, { method: 'DELETE' });
            renderLibrary();
            showToast('تم الحذف'); }

        async function saveBook(e) {
            e.preventDefault();
            const data = {
                title: document.getElementById('bTitle').value.trim(),
                author: document.getElementById('bAuthor').value.trim(),
                isbn: document.getElementById('bIsbn').value.trim(),
                status: document.getElementById('bStatus').value,
            };
            if (!data.title) { showToast('أدخل العنوان', 'error'); return false; }
            try {
                await fetchApi('/books', { method: 'POST', body: JSON.stringify(data) });
                closeModal('bookModal');
                renderLibrary();
                showToast('تم الإضافة');
            } catch (err) { showToast(err.message, 'error'); }
            return false;
        }

        // Reports
        function generateReport(type) {
            const output = document.getElementById('reportOutput');
            fetchApi('/dashboard').then(dash => {
                let html = `<h4><i class="fas fa-file-alt"></i> تقرير ${type === 'attendance' ? 'الحضور' : 'المالي'}</h4>`;
                if (type === 'attendance') {
                    html +=
                        `<p>عدد الطالبات: ${dash.students}، نسبة الحضور: ${dash.attendance_rate}%، عدد الحضور اليوم: ${dash.today_attendance}</p>`;
                } else {
                    fetchApi('/payments').then(p => {
                        const inc = p.filter(x => x.type === 'دخل').reduce((s, x) => s + x.amount, 0);
                        const exp = p.filter(x => x.type === 'مصروف').reduce((s, x) => s + x.amount, 0);
                        html += `<p>الإيرادات: ${inc} ج.م، المصروفات: ${exp} ج.م، الرصيد: ${inc-exp} ج.م</p>`;
                        output.innerHTML = html;
                    });
                    return;
                }
                output.innerHTML = html;
            }).catch(console.error);
        }

        // Profile & Settings
        function updateProfile() {
            if (!currentUser) return;
            document.getElementById('profileAvatar').textContent = currentUser.avatar || currentUser.name[0];
            document.getElementById('profileName').textContent = currentUser.name;
            document.getElementById('profileRole').textContent = currentUser.role;
            document.getElementById('userName').textContent = currentUser.name;
            document.getElementById('userAvatar').textContent = currentUser.avatar || currentUser.name[0];
        }

        async function changePassword() {
            const newPw = document.getElementById('newPassword').value.trim();
            if (!newPw || newPw.length < 4) { showToast('كلمة مرور 4 أحرف على الأقل', 'error'); return; }
            // Note: For simplicity, we don't have change password endpoint in this demo, but you can add it.
            showToast('تم التغيير (تجريبي)');
        }

        function saveSettings() {
            const name = document.getElementById('schoolName').value;
            const year = document.getElementById('academicYear').value;
            localStorage.setItem('sms_school_name', name);
            localStorage.setItem('sms_academic_year', year);
            showToast('تم حفظ الإعدادات');
        }

        // ============================================================
        // التهيئة
        // ============================================================
        function initApp() {
            const theme = localStorage.getItem('sms_theme') || 'light';
            document.documentElement.setAttribute('data-theme', theme);
            document.getElementById('themeIcon').className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
            loadSettings();
            updateProfile();
            renderSidebar();
            updateDashboard();
            renderStudents();
            renderTeachers();
            renderClasses();
            renderAttendance();
            renderExams();
            renderFinance();
            renderLibrary();
            document.getElementById('attendanceDate').value = new Date().toISOString().split('T')[0];
            // Close sidebar on mobile
            document.querySelectorAll('.nav-item').forEach(el => {
                el.addEventListener('click', () => { if (window.innerWidth <= 768) document.getElementById('sidebar')
                        .classList.remove('open'); });
            });
        }

        function loadSettings() {
            const name = localStorage.getItem('sms_school_name') || 'مدرسة أحمد عبدالرحيم الثانوية للبنات';
            const year = localStorage.getItem('sms_academic_year') || '2025-2026';
            document.getElementById('schoolName').value = name;
            document.getElementById('academicYear').value = year;
        }

        // جعل الدوال عامة
        window.handleLogin = handleLogin;
        window.logout = logout;
        window.toggleSidebar = toggleSidebar;
        window.toggleTheme = toggleTheme;
        window.navigateTo = navigateTo;
        window.openModal = openModal;
        window.closeModal = closeModal;
        window.openStudentModal = openStudentModal;
        window.editStudent = editStudent;
        window.deleteStudent = deleteStudent;
        window.saveStudent = saveStudent;
        window.openTeacherModal = openTeacherModal;
        window.editTeacher = editTeacher;
        window.deleteTeacher = deleteTeacher;
        window.saveTeacher = saveTeacher;
        window.openClassModal = openClassModal;
        window.editClass = editClass;
        window.deleteClass = deleteClass;
        window.saveClass = saveClass;
        window.saveAttendance = saveAttendance;
        window.openAttendanceModal = () => { document.getElementById('attDate').value = new Date().toISOString().split(
                'T')[0];
            openModal('attendanceModal'); };
        window.openExamModal = () => { document.getElementById('eDate').value = new Date().toISOString().split('T')[0];
            openModal('examModal'); };
        window.deleteExam = deleteExam;
        window.saveExam = saveExam;
        window.openPaymentModal = () => { document.getElementById('pDate').value = new Date().toISOString().split('T')[0];
            openModal('paymentModal'); };
        window.savePayment = savePayment;
        window.openBookModal = () => { openModal('bookModal'); };
        window.saveBook = saveBook;
        window.deleteBook = deleteBook;
        window.generateReport = generateReport;
        window.generateAIInsights = generateAIInsights;
        window.changePassword = changePassword;
        window.saveSettings = saveSettings;
        window.renderStudents = renderStudents;
        window.renderTeachers = renderTeachers;
        window.renderClasses = renderClasses;
        window.renderAttendance = renderAttendance;
        window.renderExams = renderExams;
        window.renderFinance = renderFinance;
        window.renderLibrary = renderLibrary;
        window.updateDashboard = updateDashboard;
        window.updateProfile = updateProfile;

        // فحص إذا كان هناك توكن
        if (getToken()) {
            document.getElementById('loginPage').style.display = 'none';
            document.getElementById('appShell').style.display = 'block';
            // جلب بيانات المستخدم من التوكن (نحاول)
            fetchApi('/dashboard').then(() => {
                // نجاح
                currentUser = { name: 'مستخدم', role: 'admin' }; // سيتم تحديثه لاحقاً
                initApp();
            }).catch(() => {
                logout();
            });
        }

        console.log('🚀 نظام بايثون + FastAPI جاهز!');
        console.log('👤 admin@school.com / admin123');
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return HTML_TEMPLATE

# ============================
# تشغيل الخادم
# ============================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
