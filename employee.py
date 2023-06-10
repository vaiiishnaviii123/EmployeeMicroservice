from boto3.dynamodb.conditions import Attr
from flask import Flask, request, jsonify, redirect, session, url_for
import socket
import boto3
import json
import datetime
from datetime import timedelta
import os
import random
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from decorator import login_required

app = Flask(__name__)

s3_client = boto3.client('s3')
s3 = boto3.resource('s3')
my_bucket = s3.Bucket("employeeprofilephotos")
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
db_table = dynamodb.Table('employee')

date_format = '%m-%d-%y'

# Session config
app.secret_key = 'random secret'
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

# oAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='787984224372-t56fhi955jd0ie9c25849dtg5pc0muh2.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
)


@app.route('/login')
def login():
    google = oauth.create_client('google')  # create the google oauth client
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')  # create the google oauth client
    token = google.authorize_access_token()  # Access token from google (needed to get user info)
    resp = google.get('userinfo', token=token)  # userinfo contains stuff u specificed in the scrope
    user_info = resp.json()
    session['profile'] = user_info
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    return redirect('/')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/peoplesuite/apis/employee/<int:employeeId>/photo", methods=['POST', 'GET'])
@login_required
def employeePhoto(employeeId):
    print('inside here')
    if request.method == 'GET':
        try:
            empId = employeeId
            if len(str(empId)) != 7:
                return 'Employee Id should be a 7 digit number'
            # Get the file from the S3 Bucket created
            for file in my_bucket.objects.filter(Prefix=str(empId)):
                file_name = file.key
                print(file.key)
                if file_name.find(".png") != -1 or file_name.find(".jpeg") != -1 or file_name.find(".jpg") != -1:
                    s3_response = s3_client.download_file(
                        Bucket='employeeprofilephotos',
                        Key=file.key,
                        Filename='./photo.jpeg'
                    )
            return 'Photo downloaded successfully'
        except s3_client.exceptions.NoSuchBucket as e:
            print('The S3 bucket does not exist.')
            print(e)

        except s3_client.exceptions.NoSuchKey as e:
            print('The S3 objects does not exist in the S3 bucket.')
            print(e)
    else:
        print('inside here')
        if 'file' not in request.files:
            return 'Please attach file'
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            return 'Please select a file'
        if file and allowed_file(file.filename):
            fileExtension = file.filename.rsplit('.', 1)[1]
            print(fileExtension)
            fileName = str(employeeId) + '.' + fileExtension
            filename = secure_filename(file.filename)
            print(fileName)
            my_bucket.upload_fileobj(file, fileName)
        return "File uploaded successfully!!"


@app.route("/peoplesuite/apis/employees/<int:employeeId>/profile", methods=['GET'])
@login_required
def getEmployeeProfile(employeeId):
    print('inside get profile')
    response = db_table.get_item(
        Key={
            'employeeId': employeeId,
        }
    )
    item = response['Item']
    print(item)
    return item


@app.route("/peoplesuite/apis/employees/<int:employeeId>/profile", methods=['POST'])
@login_required
def saveEmployeeProfile(employeeId):
    print('inside get profile')
    print(request.data)
    data = json.loads(request.data.decode('utf-8'))
    verify_request_data(data)
    print(data)
    # data['employeeId'] = random.randint(1000000, 9999999)
    db_table.put_item(
        Item=data
    )
    return 'Employee Profile added successfully.'


@app.route("/peoplesuite/apis/employees", methods=['GET'])
@login_required
def getEmployeesOfDepartment():
    depId = request.args.get('departmentId')
    print('inside get employee profile on departmentId', depId, type(depId))

    response = db_table.scan(FilterExpression=Attr('departmentID').eq(depId))
    data = response['Items']

    while 'LastEvaluatedKey' in response:
        response = db_table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        data.extend(response['Items'])
    print(data)
    return data


def verify_request_data(data):
    if len(str(data['employeeId'])) != 7:
        return 'Employee Id should be a 7 digit number'
    if len(data['country']) > 3 or len(data['country']) < 2:
        return 'Country code needs to be ISO 3166'
    try:
        if data['startDate'] != datetime.strptime(data['startDate'], "%m-%d-%Y").strftime('%m-%d-%Y'):
            raise ValueError
    except ValueError:
        return "Incorrect data format, should be YYYY-MM-DD"


@app.route("/peoplesuite/apis/employee/servicem")
def hello_employee_service():
    return "<p> Welcome to employee service</p>"


@app.route("/peoplesuite/apis/employee/health")
def health():
    return jsonify(
        status="Employee service UP and running"
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
