#Model
class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    university_id = db.Column(db.Integer, db.ForeignKey('university.id'), nullable=False)
    status = db.Column(db.String(50), default='Pending')

#Schema
class ApplicationSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Application
