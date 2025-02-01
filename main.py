from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://retailerdb_user:ruQ9WrHQ11zAe0ZgwYNgBdwycb4Yp6wt@dpg-cue9vidsvqrc73d7ese0-a.oregon-postgres.render.com/retailerdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)

# Models
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    marks = db.Column(db.Float, nullable=False)

class University(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    required_marks = db.Column(db.Float, nullable=False)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    university_id = db.Column(db.Integer, db.ForeignKey('university.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    status = db.Column(db.String(50), default='Pending')

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    aps_requirement = db.Column(db.Int, nullable=False)

#Schema
class CourseSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Course

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

# Routes
@app.route('/students', methods=['POST'])
def add_student():
    name = request.json['name']
    marks = request.json['marks']
    new_student = Student(name=name, marks=marks)
    db.session.add(new_student)
    db.session.commit()
    return student_schema.jsonify(new_student)

@app.route('/universities', methods=['POST'])
def add_university():
    name = request.json['name']
    required_marks = request.json['required_marks']
    new_university = University(name=name, required_marks=required_marks)
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
    db.create_all()
    app.run(debug=True)
