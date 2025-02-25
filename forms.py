from flask_wtf import FlaskForm
from wtforms import BooleanField 
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField, SelectField, FloatField, MultipleFileField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    terms = BooleanField('I agree to the terms', validators=[DataRequired()]) 
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class MeterReadingForm(FlaskForm):
    reading = StringField('Meter Reading', validators=[DataRequired()])
    image = FileField('Upload Meter Image')
    submit = SubmitField('Submit')

class FaultReportForm(FlaskForm):
    category = SelectField(
        'Fault Category', 
        choices=[
            ('Pipe Burst', 'Pipe Burst'),
            ('Water Quality', 'Water Quality'),
            ('Meter Issue', 'Meter Issue'),
            ('No Water Supply', 'No Water Supply'),
            ('Other', 'Other')
        ], 
        validators=[DataRequired()]
    )
    description = TextAreaField('Description', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])  # Use address instead of location
    latitude = FloatField('Latitude', validators=[DataRequired(message="Latitude is required.")])
    location = StringField('Location', validators=[DataRequired(message="Location is required.")])
    longitude = FloatField('Longitude', validators=[DataRequired(message="Longitude is required.")])
    # If you want to support multiple images:
    fault_images = MultipleFileField('Fault Images', validators=[Optional()])