import os
import uuid
import logging
from functools import wraps
from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from flask_caching import Cache
from werkzeug.utils import secure_filename
import jwt
from sqlalchemy.orm import joinedload
from marshmallow import Schema, fields, validate
import requests

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://localhost/dbunilink')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')  # Ensure this is set in production
app.config['UPLOAD_FOLDER'] = 'uploads'
CORS(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
YOCO_SECRET_KEY = os.environ.get('YOCO_SECRET_KEY')

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Models with Indexes
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    applications = db.relationship('Application', backref='user', lazy=True)
    subscriptions = db.relationship('Subscription', backref='user', lazy=True)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    contact_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    marks = db.Column(db.Float, nullable=False)
    gpa = db.Column(db.Float, nullable=False)
    applications = db.relationship('Application', backref='student', lazy=True)

class University(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    name = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    contact_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    courses = db.relationship('Course', backref='university', lazy=True)
    applications = db.relationship('Application', backref='university', lazy=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    name = db.Column(db.String(255), nullable=False)
    duration = db.Column(db.String(50), nullable=False)
    tuition_fees = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    aps_requirement = db.Column(db.Integer, nullable=False)
    university_id = db.Column(db.Integer, db.ForeignKey('university.id'), nullable=False, index=True)
    applications = db.relationship('Application', backref='course', lazy=True)
    faculty = db.Column(db.String(100), nullable=False)
    requirements = db.Column(db.String(255), nullable=False)
    application_status = db.Column(db.String(50), default='Open')

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False, index=True)
    university_id = db.Column(db.Integer, db.ForeignKey('university.id'), nullable=False, index=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False, index=True)
    application_date = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    decision_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), default='Pending')
    application_fee = db.Column(db.Float, nullable=False)
    notes = db.Column(db.Text, nullable=True)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=False, index=True)
    document_type = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    uploaded_date = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    plan_name = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), default="ZAR")
    status = db.Column(db.String(20), default="active")
    start_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    end_date = db.Column(db.DateTime, nullable=True)

# Enhanced Schemas with Validation
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        exclude = ('password',)  # Don't expose password
    username = fields.Str(required=True, validate=validate.Length(max=80))
    email = fields.Email(required=True, validate=validate.Length(max=100))

class StudentSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Student
    email = fields.Email(required=True)

class UniversitySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = University

class CourseSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Course

class ApplicationSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Application
        include_relationships = True

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

# JWT Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            token = token.split(" ")[1]  # Assuming "Bearer <token>"
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Blueprints for Modular Structure
universities_bp = Blueprint('universities', __name__)
courses_bp = Blueprint('courses', __name__)
applications_bp = Blueprint('applications', __name__)
documents_bp = Blueprint('documents', __name__)
subscriptions_bp = Blueprint('subscriptions', __name__)

# Routes with Improvements
@app.route('/', methods=['GET'])
def home():
    return '''
        <p style="text-align: center; font-size: 48px;">
            Welcome to UniLink Backend service
        </p>
    '''

@universities_bp.route('/', methods=['POST'])
@token_required
def add_university(current_user):
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
    logger.info(f"User {current_user.username} added university: {new_university.name}")
    return university_schema.jsonify(new_university), 201

@universities_bp.route('/', methods=['GET'])
@cache.cached(timeout=300)  # Cache for 5 minutes
def get_universities():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    universities = University.query.paginate(page=page, per_page=limit, error_out=False).items
    logger.info(f"Fetched universities - Page: {page}, Limit: {limit}")
    return universities_schema.jsonify(universities), 200

@courses_bp.route('/', methods=['POST'])
@token_required
def add_course(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400
    required_fields = ['name', 'duration', 'tuition_fees', 'aps_requirement', 'university_id', 'faculty', 'requirements']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400
    new_course = Course(
        name=data['name'],
        duration=data['duration'],
        tuition_fees=data['tuition_fees'],
        description=data.get('description', ''),
        aps_requirement=data['aps_requirement'],
        university_id=data['university_id'],
        faculty=data['faculty'],
        requirements=data['requirements'],
        application_status=data.get('application_status', 'Open')
    )
    db.session.add(new_course)
    db.session.commit()
    logger.info(f"User {current_user.username} added course: {new_course.name}")
    return course_schema.jsonify(new_course), 201

@courses_bp.route('/', methods=['GET'])
@cache.cached(timeout=300)
def get_courses():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    courses = Course.query.paginate(page=page, per_page=limit, error_out=False).items
    return courses_schema.jsonify(courses), 200

@courses_bp.route('/saved_courses', methods=['GET'])
@token_required
def get_saved_courses(current_user):
    user_id = request.args.get('user_id')
    if not user_id or int(user_id) != current_user.id:
        return jsonify({'message': 'Invalid or missing user_id'}), 400
    students = Student.query.filter_by(user_id=user_id).all()
    if not students:
        return jsonify([]), 200
    student_ids = [student.id for student in students]
    saved_apps = Application.query.filter(
        Application.student_id.in_(student_ids),
        Application.status == 'Saved'
    ).options(joinedload(Application.course), joinedload(Application.university)).all()
    saved_courses = [
        {
            'status': app.course.application_status,
            'university': app.university.name,
            'course': app.course.name,
            'aps': app.course.aps_requirement,
            'requirements': app.course.requirements,
            'faculty': app.course.faculty
        } for app in saved_apps
    ]
    logger.info(f"User {current_user.username} fetched saved courses")
    return jsonify(saved_courses), 200

@applications_bp.route('/apply', methods=['POST'])
@token_required
def apply(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400
    required_fields = ['student_id', 'university_id', 'course_id', 'application_fee']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400
    student = Student.query.get(data['student_id'])
    if student.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized'}), 403
    university = University.query.get(data['university_id'])
    course = Course.query.get(data['course_id'])
    if not student or not university or not course:
        return jsonify({'message': 'Student, University, or Course not found'}), 404
    new_application = Application(
        student_id=data['student_id'],
        university_id=data['university_id'],
        course_id=data['course_id'],
        application_fee=data['application_fee'],
        status='Pending'
    )
    db.session.add(new_application)
    db.session.commit()
    logger.info(f"User {current_user.username} applied for course {course.name}")
    return application_schema.jsonify(new_application), 201

@applications_bp.route('/', methods=['GET'])
@token_required
def get_applications(current_user):
    applications = Application.query.options(
        joinedload(Application.student),
        joinedload(Application.university),
        joinedload(Application.course)
    ).all()
    logger.info(f"User {current_user.username} fetched all applications")
    return applications_schema.jsonify(applications), 200

@applications_bp.route('/save', methods=['POST'])
@token_required
def save_application(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400
    required_fields = ['student_id', 'university_id', 'course_id', 'application_fee', 'user_id']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400
    if int(data['user_id']) != current_user.id:
        return jsonify({'message': 'Unauthorized'}), 403
    student = Student.query.get(data['student_id'])
    university = University.query.get(data['university_id'])
    course = Course.query.get(data['course_id'])
    if not student or not university or not course:
        return jsonify({'message': 'Invalid student, university, or course ID'}), 404
    if student.user_id != current_user.id:
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
    logger.info(f"User {current_user.username} saved application for course {course.name}")
    return jsonify({'message': 'Application saved successfully', 'application': application_schema.dump(new_application)}), 201

@documents_bp.route('/', methods=['POST'])
@token_required
def add_document_json(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400
    required_fields = ['application_id', 'document_type', 'file_path']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400
    application = Application.query.get(data['application_id'])
    if not application or application.student.user_id != current_user.id:
        return jsonify({'message': 'Application not found or unauthorized'}), 404
    new_document = Document(
        application_id=data['application_id'],
        document_type=data['document_type'],
        file_path=data['file_path']
    )
    db.session.add(new_document)
    db.session.commit()
    logger.info(f"User {current_user.username} added document for application {new_document.application_id}")
    return document_schema.jsonify(new_document), 201

@documents_bp.route('/', methods=['GET'])
@token_required
def get_documents(current_user):
    documents = Document.query.options(joinedload(Document.application)).all()
    logger.info(f"User {current_user.username} fetched all documents")
    return documents_schema.jsonify(documents), 200

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@documents_bp.route('/upload', methods=['POST'])
@token_required
def upload_document(current_user):
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'message': 'Invalid file'}), 400
    application_id = request.form.get('application_id')
    if not application_id:
        return jsonify({'message': 'application_id is required'}), 400
    application = Application.query.get(application_id)
    if not application or application.student.user_id != current_user.id:
        return jsonify({'message': 'Application not found or unauthorized'}), 404
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(file_path)
    new_document = Document(
        application_id=application_id,
        document_type=request.form.get('document_type', 'report_card'),
        file_path=file_path
    )
    db.session.add(new_document)
    db.session.commit()
    logger.info(f"User {current_user.username} uploaded document {unique_filename}")
    return document_schema.jsonify(new_document), 201

@subscriptions_bp.route('/', methods=['POST'])
@token_required
def subscribe(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400
    user_id = data.get('user_id')
    if not user_id or int(user_id) != current_user.id:
        return jsonify({'message': 'Invalid or missing user_id'}), 400
    amount = data.get('amount')
    plan_name = data.get('plan_name')
    token = data.get('token')
    if not token or not amount or not plan_name:
        return jsonify({'message': 'Missing required fields'}), 400
    if not YOCO_SECRET_KEY:
        return jsonify({'message': 'Payment service unavailable'}), 503
    headers = {"Content-Type": "application/json", "X-Auth-Secret-Key": YOCO_SECRET_KEY}
    payload = {"token": token, "amountInCents": amount, "currency": "ZAR"}
    try:
        yoco_response = requests.post("https://online.yoco.com/v1/charges/", json=payload, headers=headers)
        if yoco_response.status_code == 200:
            new_subscription = Subscription(
                user_id=user_id,
                plan_name=plan_name,
                amount=amount / 100,
                status="active"
            )
            db.session.add(new_subscription)
            db.session.commit()
            logger.info(f"User {current_user.username} subscribed to {plan_name}")
            return jsonify({'message': 'Subscription successful', 'subscription': plan_name}), 201
        else:
            return jsonify({'message': 'Payment failed', 'error': yoco_response.json()}), 400
    except requests.exceptions.RequestException as e:
        logger.error(f"Payment error for {current_user.username}: {str(e)}")
        return jsonify({'message': 'Payment service error', 'error': str(e)}), 500

@subscriptions_bp.route('/', methods=['GET'])
@token_required
def get_subscriptions(current_user):
    user_id = request.args.get('user_id')
    if not user_id or int(user_id) != current_user.id:
        return jsonify({'message': 'Invalid or missing user_id'}), 400
    subscriptions = Subscription.query.filter_by(user_id=user_id).all()
    logger.info(f"User {current_user.username} fetched subscriptions")
    return jsonify([{
        "plan_name": sub.plan_name,
        "amount": sub.amount,
        "currency": sub.currency,
        "status": sub.status,
        "start_date": sub.start_date
    } for sub in subscriptions]), 200

@subscriptions_bp.route('/cancel', methods=['POST'])
@token_required
def cancel_subscription(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400
    subscription_id = data.get('subscription_id')
    user_id = data.get('user_id')
    if not subscription_id or not user_id or int(user_id) != current_user.id:
        return jsonify({'message': 'Missing or invalid subscription_id/user_id'}), 400
    subscription = Subscription.query.filter_by(id=subscription_id, user_id=user_id).first()
    if not subscription:
        return jsonify({'message': 'Subscription not found'}), 404
    subscription.status = "cancelled"
    db.session.commit()
    logger.info(f"User {current_user.username} cancelled subscription {subscription_id}")
    return jsonify({'message': 'Subscription cancelled successfully'}), 200

@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    return jsonify({'message': 'Access granted'}), 200

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Server error: {str(error)}")
    return jsonify({'message': 'Internal server error'}), 500

# Register Blueprints
app.register_blueprint(universities_bp, url_prefix='/universities')
app.register_blueprint(courses_bp, url_prefix='/courses')
app.register_blueprint(applications_bp, url_prefix='/applications')
app.register_blueprint(documents_bp, url_prefix='/documents')
app.register_blueprint(subscriptions_bp, url_prefix='/subscriptions')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port, debug=False)