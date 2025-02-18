#Model
class University(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    required_marks = db.Column(db.Float, nullable=False)

#Schema
class UniversitySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = University
