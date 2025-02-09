from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from datetime import timedelta
import os
import requests

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://retailerdb_user:ruQ9WrHQ11zAe0ZgwYNgBdwycb4Yp6wt@dpg-cue9vidsvqrc73d7ese0-a.oregon-postgres.render.com/retailerdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this to a secure key in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
YOCO_SECRET_KEY = "your_yoco_secret_key"

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)
ma = Marshmallow(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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

# Routes
@app.route('/', methods=['GET'])
def home():
    return '''
        <p style="text-align: center; font-size: 48px;">
            Welcome to UniLink Backend service
        </p>
    '''

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/students/register', methods=['POST'])
@jwt_required()
def add_student():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    new_student = Student(
        name=data['name'],
        date_of_birth=data['date_of_birth'],
        contact_number=data['contact_number'],
        email=data['email'],
        address=data['address'],
        marks=data['marks'],
        gpa=data['gpa']
    )
    db.session.add(new_student)
    db.session.commit()
    return student_schema.jsonify(new_student), 201

@app.route('/students', methods=['GET'])
@jwt_required()
def get_students():
    students = Student.query.all()
    return students_schema.jsonify(students), 200

@app.route('/universities', methods=['POST'])
@jwt_required()
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
@jwt_required()
def get_universities():
    universities = University.query.all()
    return universities_schema.jsonify(universities), 200

@app.route('/courses', methods=['POST'])
@jwt_required()
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
@jwt_required()
def get_courses():
    courses = Course.query.all()
    return courses_schema.jsonify(courses), 200

@app.route('/apply', methods=['POST'])
@jwt_required()
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
@jwt_required()
def get_applications():
    applications = Application.query.all()
    return applications_schema.jsonify(applications), 200

@app.route('/documents', methods=['POST'])
@jwt_required()
def add_document():
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
@jwt_required()
def get_documents():
    documents = Document.query.all()
    return documents_schema.jsonify(documents), 200

@app.route('/subscribe', methods=['POST'])
@jwt_required()
def subscribe():
    data = request.get_json()
    user_id = get_jwt_identity()
    amount = data.get('amount')  # Amount in cents (e.g., R100 = 10000)
    plan_name = data.get('plan_name')
    token = data.get('token')  # Yoco token from frontend

    if not token or not amount or not plan_name:
        return jsonify({'message': 'Missing required fields'}), 400

    # Make Yoco API request
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
            amount=amount / 100,  # Convert to Rands
            status="active"
        )
        db.session.add(new_subscription)
        db.session.commit()

        return jsonify({'message': 'Subscription successful', 'subscription': plan_name}), 201

    return jsonify({'message': 'Payment failed', 'error': yoco_response.json()}), 400

@app.route('/subscriptions', methods=['GET'])
@jwt_required()
def get_subscriptions():
    user_id = get_jwt_identity()
    subscriptions = Subscription.query.filter_by(user_id=user_id).all()
    return jsonify([{
        "plan_name": sub.plan_name,
        "amount": sub.amount,
        "currency": sub.currency,
        "status": sub.status,
        "start_date": sub.start_date
    } for sub in subscriptions]), 200

@app.route('/subscriptions/cancel', methods=['POST'])
@jwt_required()
def cancel_subscription():
    data = request.get_json()
    subscription_id = data.get('subscription_id')
    user_id = get_jwt_identity()

    subscription = Subscription.query.filter_by(id=subscription_id, user_id=user_id).first()
    
    if not subscription:
        return jsonify({'message': 'Subscription not found'}), 404

    subscription.status = "cancelled"
    db.session.commit()
    
    return jsonify({'message': 'Subscription cancelled successfully'}), 200

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': 'Access granted', 'user_id': current_user}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port, debug=False)