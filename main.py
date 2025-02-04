from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

from flask_bcrypt import Bcrypt
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://retailerdb_user:ruQ9WrHQ11zAe0ZgwYNgBdwycb4Yp6wt@dpg-cue9vidsvqrc73d7ese0-a.oregon-postgres.render.com/retailerdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)
ma = Marshmallow(app)
app.app_context().push()
db.create_all()

# Models
# User Model
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

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    duration = db.Column(db.String(50), nullable=False)  # e.g., "4 years", "2 years"
    tuition_fees = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    aps_requirement = db.Column(db.Integer, nullable=False)
    university_id = db.Column(db.Integer, db.ForeignKey('university.id'), nullable=False)
    applications = db.relationship('Application', backref='course', lazy=True)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=False)
    document_type = db.Column(db.String(100), nullable=False)  # e.g., Transcript, Recommendation Letter
    file_path = db.Column(db.String(255), nullable=False)  # Path to the uploaded file
    uploaded_date = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)

class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
#Schema
class CourseSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Course

class DocumentSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Document

# Schemas
class StudentSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Student

class UniversitySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = University

class ApplicationSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Application

student_schema = StudentSchema()
students_schema = StudentSchema(many=True)
university_schema = UniversitySchema()
universities_schema = UniversitySchema(many=True)
application_schema = ApplicationSchema()
applications_schema = ApplicationSchema(many=True)
course_schema = CourseSchema()
courses_schema = CourseSchema(many=True)
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
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))
        return jsonify(access_token=access_token)
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/students/register', methods=['POST'])
@jwt_required()
def add_student():
    data = request.get_json()
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
    return students_schema.jsonify(students)

@app.route('/universities', methods=['POST'])
def add_university():
    name = request.json['name']
    required_marks = request.json['required_marks']
    new_university = University(name=name)
    db.session.add(new_university)
    db.session.commit()
    return university_schema.jsonify(new_university)

@app.route('/apply/<int:student_id>/<int:university_id>', methods=['POST'])
def apply(student_id, university_id):
    student = Student.query.get(student_id)
    university = University.query.get(university_id)
    if not student or not university:
        return jsonify({'message': 'Student or University not found'}), 404
    status = 'Accepted' if student.marks >= university.required_marks else 'Rejected'
    application = Application(student_id=student_id, university_id=university_id, status=status)
    db.session.add(application)
    db.session.commit()
    return application_schema.jsonify(application)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    db.create_all()
    app.run(host="0.0.0.0", port=port, debug=False)
