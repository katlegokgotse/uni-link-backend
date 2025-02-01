class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=Flase)
    aps_requirement = db.Column(db.Int, nullable=False)

#Schema
class CourseSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Course
