from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_cors import CORS
from datetime import timedelta
import os
import requests

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://dbunilink_user:7Is1S6y4pYXJuGNG26xNMy02gstj04wI@dpg-cuq59mtsvqrc73f7dnog-a.oregon-postgres.render.com/dbunilink'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Removed JWT configuration
CORS(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)

YOCO_SECRET_KEY = "your_yoco_secret_key"

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    # Additional relationships can be added as needed

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    contact_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    marks = db.Column(db.Float, nullable=False)
    gpa = db.Column(db.Float, nullable=False)
    applications = db.relationship('Application', backref='student', lazy=True)

class University(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    contact_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    courses = db.relationship('Course', backref='university', lazy=True)
    applications = db.relationship('Application', backref='university', lazy=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    duration = db.Column(db.String(50), nullable=False)
    tuition_fees = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    aps_requirement = db.Column(db.Integer, nullable=False)
    university_id = db.Column(db.Integer, db.ForeignKey('university.id'), nullable=False)
    applications = db.relationship('Application', backref='course', lazy=True)
    faculty = db.Column(db.String(100), nullable=False)
    requirements = db.Column(db.String(255), nullable=False)
    application_status = db.Column(db.String(50), default='Open')
class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    university_id = db.Column(db.Integer, db.ForeignKey('university.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    application_date = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    decision_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), default='Pending')
    application_fee = db.Column(db.Float, nullable=False)
    notes = db.Column(db.Text, nullable=True)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=False)
    document_type = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    uploaded_date = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    plan_name = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), default="ZAR")
    status = db.Column(db.String(20), default="active")
    start_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    end_date = db.Column(db.DateTime, nullable=True)

# Schemas
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User

class StudentSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Student

class UniversitySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = University

class CourseSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Course

class ApplicationSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Application

class DocumentSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Document

class SubscriptionSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Subscription

user_schema = UserSchema()
student_schema = StudentSchema()
students_schema = StudentSchema(many=True)
university_schema = UniversitySchema()
universities_schema = UniversitySchema(many=True)
course_schema = CourseSchema()
courses_schema = CourseSchema(many=True)
application_schema = ApplicationSchema()
applications_schema = ApplicationSchema(many=True)
document_schema = DocumentSchema()
documents_schema = DocumentSchema(many=True)
subscription_schema = SubscriptionSchema()

# Routes
@app.route('/', methods=['GET'])
def home():
    return '''
        <p style="text-align: center; font-size: 48px;">
            Welcome to UniLink Backend service
        </p>
    '''

@app.route('/universities', methods=['POST'])
def add_university():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    new_university = University(
        name=data['name'],
        location=data['location'],
        contact_number=data['contact_number'],
        email=data['email'],
        description=data.get('description', '')
    )
    db.session.add(new_university)
    db.session.commit()
    return university_schema.jsonify(new_university), 201

@app.route('/universities', methods=['GET'])
def get_universities():
    universities = University.query.all()
    return universities_schema.jsonify(universities), 200

@app.route('/courses', methods=['POST'])
def add_course():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    new_course = Course(
        name=data['name'],
        duration=data['duration'],
        tuition_fees=data['tuition_fees'],
        description=data.get('description', ''),
        aps_requirement=data['aps_requirement'],
        university_id=data['university_id']
    )
    db.session.add(new_course)
    db.session.commit()
    return course_schema.jsonify(new_course), 201

@app.route('/courses', methods=['GET'])
def get_courses():
    courses = Course.query.all()
    return courses_schema.jsonify(courses), 200
@app.route('/courses/saved_courses', methods=['GET'])
def get_saved_courses():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'message': 'user_id is required'}), 400

    students = Student.query.filter_by(user_id=user_id).all()
    if not students:
        return jsonify([]), 200

    student_ids = [student.id for student in students]
    saved_apps = Application.query.filter(
        Application.student_id.in_(student_ids),
        Application.status == 'Saved'
    ).all()

    saved_courses = []
    for app in saved_apps:
        course = Course.query.get(app.course_id)
        if course:
            university = University.query.get(course.university_id)
            saved_courses.append({
                'status': course.application_status,
                'university': university.name,
                'course': course.name,
                'aps': course.aps_requirement,
                'requirements': course.requirements,
                'faculty': course.faculty
            })

    return jsonify(saved_courses), 200
@app.route('/apply', methods=['POST'])
def apply():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    student_id = data.get('student_id')
    university_id = data.get('university_id')
    course_id = data.get('course_id')
    application_fee = data.get('application_fee')

    if not student_id or not university_id or not course_id or not application_fee:
        return jsonify({'message': 'Missing required fields'}), 400

    student = Student.query.get(student_id)
    university = University.query.get(university_id)
    course = Course.query.get(course_id)

    if not student or not university or not course:
        return jsonify({'message': 'Student, University, or Course not found'}), 404

    new_application = Application(
        student_id=student_id,
        university_id=university_id,
        course_id=course_id,
        application_fee=application_fee,
        status='Pending'
    )
    db.session.add(new_application)
    db.session.commit()
    return application_schema.jsonify(new_application), 201

@app.route('/applications', methods=['GET'])
def get_applications():
    applications = Application.query.all()
    return applications_schema.jsonify(applications), 200

@app.route('/applications/save', methods=['POST'])
def save_application():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    required_fields = ['student_id', 'university_id', 'course_id', 'application_fee', 'user_id']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400

    user_id = data.get('user_id')

    student = Student.query.get(data['student_id'])
    university = University.query.get(data['university_id'])
    course = Course.query.get(data['course_id'])

    if not student or not university or not course:
        return jsonify({'message': 'Invalid student, university, or course ID'}), 404

    # Ensure that the student belongs to the provided user_id
    if student.user_id != user_id:
        return jsonify({'message': 'Unauthorized'}), 403

    new_application = Application(
        student_id=data['student_id'],
        university_id=data['university_id'],
        course_id=data['course_id'],
        application_fee=data['application_fee'],
        status='Saved'
    )

    db.session.add(new_application)
    db.session.commit()

    return jsonify({'message': 'Application saved successfully', 'application': application_schema.dump(new_application)}), 201

@app.route('/documents', methods=['POST'])
def add_document_json():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    new_document = Document(
        application_id=data['application_id'],
        document_type=data['document_type'],
        file_path=data['file_path']
    )
    db.session.add(new_document)
    db.session.commit()
    return document_schema.jsonify(new_document), 201

@app.route('/documents', methods=['GET'])
def get_documents():
    documents = Document.query.all()
    return documents_schema.jsonify(documents), 200

@app.route('/documents/upload', methods=['POST'])
def upload_document():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    upload_folder = 'uploads'
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, file.filename)
    file.save(file_path)
    
    new_document = Document(
        application_id=request.form.get('application_id', 0),
        document_type=request.form.get('document_type', 'report_card'),
        file_path=file_path
    )
    db.session.add(new_document)
    db.session.commit()
    return document_schema.jsonify(new_document), 201

@app.route('/subscribe', methods=['POST'])
def subscribe():
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'message': 'user_id is required'}), 400

    amount = data.get('amount')
    plan_name = data.get('plan_name')
    token = data.get('token')

    if not token or not amount or not plan_name:
        return jsonify({'message': 'Missing required fields'}), 400

    headers = {
        "Content-Type": "application/json",
        "X-Auth-Secret-Key": YOCO_SECRET_KEY
    }
    payload = {
        "token": token,
        "amountInCents": amount,
        "currency": "ZAR"
    }
    yoco_response = requests.post("https://online.yoco.com/v1/charges/", json=payload, headers=headers)
    
    if yoco_response.status_code == 200:
        payment_data = yoco_response.json()
        
        new_subscription = Subscription(
            user_id=user_id,
            plan_name=plan_name,
            amount=amount / 100,
            status="active"
        )
        db.session.add(new_subscription)
        db.session.commit()

        return jsonify({'message': 'Subscription successful', 'subscription': plan_name}), 201

    return jsonify({'message': 'Payment failed', 'error': yoco_response.json()}), 400

@app.route('/subscriptions', methods=['GET'])
def get_subscriptions():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'message': 'user_id is required as a query parameter'}), 400
    subscriptions = Subscription.query.filter_by(user_id=user_id).all()
    return jsonify([{
        "plan_name": sub.plan_name,
        "amount": sub.amount,
        "currency": sub.currency,
        "status": sub.status,
        "start_date": sub.start_date
    } for sub in subscriptions]), 200

@app.route('/subscriptions/cancel', methods=['POST'])
def cancel_subscription():
    data = request.get_json()
    subscription_id = data.get('subscription_id')
    user_id = data.get('user_id')

    if not subscription_id or not user_id:
        return jsonify({'message': 'Missing subscription_id or user_id'}), 400

    subscription = Subscription.query.filter_by(id=subscription_id, user_id=user_id).first()
    
    if not subscription:
        return jsonify({'message': 'Subscription not found'}), 404

    subscription.status = "cancelled"
    db.session.commit()
    
    return jsonify({'message': 'Subscription cancelled successfully'}), 200

@app.route('/protected', methods=['GET'])
def protected():
    return jsonify({'message': 'Access granted'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
