class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    marks = db.Column(db.Float, nullable=False)

class StudentSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Student
