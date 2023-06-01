import requests
from boto3.dynamodb.conditions import Attr
from flask import Flask, request, jsonify, redirect, session, url_for
import boto3
from datetime import timedelta
from authlib.integrations.flask_client import OAuth
from decorator import login_required


app = Flask(__name__)

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
db_table = dynamodb.Table('department')


# Session config
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



@app.route("/peoplesuite/apis/departments", methods=['GET'])
@login_required
def getDepartmentList():
    print('inside here')

    response = db_table.scan()
    data = response['Items']

    while 'LastEvaluatedKey' in response:
        response = db_table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        data.extend(response['Items'])
    return jsonify(data)


@app.route("/peoplesuite/apis/departments/<departmentId>/employees", methods=['GET'])
@login_required
def getDepartmentEmployees(departmentId):
    params = {'departmentId': departmentId}
    response = requests.get('http://127.0.0.1:5000//peoplesuite/apis/employees', headers={'Accept': 'application/json'},
                            params=params)
    print(f"Status Code: {response.status_code}, Content: {response.json()}")
    return response.json()


@app.route("/")
def hello_department_service():
    return "<p> Welcome to department microservice</p>"


@app.route("/health")
def health():
    return jsonify(
        status="Department service UP and running"
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
