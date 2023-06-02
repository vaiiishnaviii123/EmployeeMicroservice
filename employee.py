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
ALLOWED_EXTENSIONS = {'jpeg', 'png', 'jpg'}

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
db_table = dynamodb.Table('employee')
date_format = '%m-%d-%y'
app.secret_key = 'random secret'
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
# oAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='289040712545-gglis02d8v0em9f3fbonim8699gdb9et.apps.googleusercontent.com',
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
    # user = oauth.google.userinfo()  # uses openid endpoint to fetch user info
    # Here you use the profile/user data that you got and query your database find/register the user
    # and set ur own data in the session not the profile from google
    session['profile'] = user_info
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    return redirect('/')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/peoplesuite/apis/employee/<int:employeeId>/photo", methods=['POST', 'GET'])
def employeePhoto(employeeId):
    print('inside here')
    if request.method == 'GET':
        try:
            empId = employeeId
            # Get the file from the S3 Bucket created
            my_bucket = s3.Bucket("employeeprofilephotos")
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
        if request.method == 'POST':
            # print('inside here 1')
            # print(type(employeeId))
            # print(request.files['file'])
            # print(request.files['file'].filename)
            # check if the post request has the file part
            file = request.files['file']
            filename = request.files['file'].filename
            # if user does not select file, browser also
            # submit an empty part without filename
            # if file and allowed_file(file.filename):
            fileExtension = filename.rsplit('.', 1)[1]
            print(fileExtension)
            fileName = str(employeeId) + '.' + fileExtension
            print(fileName)
            print(type(fileName))
            s3_client.upload_fileobj(file, 'employeeprofilephotos', fileName)
            return "File uploaded successfully!!"


@app.route("/peoplesuite/apis/employees/<int:employeeId>/profile", methods=['GET', 'POST'])
# @login_required
def employeeProfile(employeeId):
    if request.method == 'POST':
        empId = employeeId
        print('inside save profile')
        print(request.data)
        data = json.loads(request.data.decode('utf-8'))
        print(data)
        data['employeeId'] = empId
        db_table.put_item(Item=data)
        return 'Employee Profile added successfully.'
    elif request.method == 'GET':
        print('inside get profile')
        response = db_table.get_item(
            Key={'employeeId': employeeId}
        )
        print(response)
        item = response['Item']
        return item


@app.route("/peoplesuite/apis/employees", methods=['GET'])
# @login_required
def getEmployeesOfDepartment():
    depId = request.args.get('departmentId')
    print('inside get employee profile on departmentId', depId, type(depId))
    response = db_table.scan(FilterExpression=Attr('departmentID').eq(depId))
    data = response['Items']
    while 'LastEvaluatedKey' in response:
        response = db_table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        data.extend(response['Items'])
    return data


@app.route("/")
def hello_employee_service():
    return "<p> Welcome to employee microservice</p>"


@app.route("/health")
def health():
    return jsonify(
        status="Employee service UP and running"
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
