import os
import pathlib
import flask
import requests
import google.auth.transport.requests
import sqlalchemy as sa
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, session, abort, redirect, request, render_template
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from random import randrange

app = Flask(__name__)

conn = "mysql+pymysql://root@localhost/resolution"

app.config['SECRET_KEY'] = 'PatrickIsTheBest'
app.config['SQLALCHEMY_DATABASE_URI'] = conn
app.secret_key = "NewYearsResolution"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" 
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json") 

db = SQLAlchemy(app)

url = "mysql+pymysql://root@localhost/resolution"
engine = create_engine(url, echo=True)

Session = sessionmaker(bind = engine)
thisSession = Session()

class Users(db.Model):
    __tablename__ = 'users'
    name = sa.Column(sa.String, primary_key=True)
    email = sa.Column(sa.String)
  
class Resolutions(db.Model):
    __tablename__ = 'resolutions'
    id = sa.Column(sa.Integer, primary_key=True)
    email = sa.Column(sa.String)
    resolution = sa.Column(sa.String)
    progress_type = sa.Column(sa.String)
    time_frame = sa.Column(sa.String)
    active = sa.Column(sa.Boolean)

flow = Flow.from_client_secrets_file( 
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],  
    redirect_uri="http://127.0.0.1:5000/callback" 
)

def login_is_required(function):  #a function to check if the user is authorized or not
    def wrapper(*args, **kwargs):
        if "google_id" not in session:  #authorization required
            return abort(401)
        else:
            return function()
    return wrapper

@app.route("/login")  #the page where the user can login
def login():
    authorization_url, state = flow.authorization_url()  #asking the flow class for the authorization (login) url
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")  #this is the page that will handle the callback process meaning process after the authorization
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  #state does not match!
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub") 
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    exists = Users.query.filter_by(email=session["email"]).first()
    if exists == None:
        user = Users(name=session["name"], email=session["email"])
        db.session.add(user)
        db.session.commit()
    return redirect("/resolutions")  # the final page where the authorized users will end up

@app.route("/logout")  #the logout page and function
def logout():
    session.clear()
    return redirect("/")

@app.route("/")  #the home page where the login button will be located
def index():
    return render_template("login.html")

@app.route("/home")
@login_is_required
def home():
    return render_template("navigation.html")

@app.route("/resolutions", methods=["GET","POST"])  #the page where only the authorized users can go to
def resolutions():
    if flask.request.method == "POST":
        resol = request.form
        resol = Resolutions(email=session["email"], resolution=resol["name"], time_frame=resol["time-frame"], progress_type=resol["progress-visual"], active=0)
        db.session.add(resol)
        db.session.commit()
        return redirect("/resolutions")
    else:
        cur_weekly = Resolutions.query.filter_by(email=session["email"], active=1, time_frame="week").first()
        cur_monthly = Resolutions.query.filter_by(email=session["email"], active=1, time_frame="month").first()
        resols = Resolutions.query.filter_by(email=session["email"]).all()
        if resols != None:
            resols = list(resols)
        else:
            resols = []
        return render_template("resolution_board.html", resols=resols, cur_weekly=cur_weekly, cur_monthly=cur_monthly)

@app.route("/achievements")
def achievements():
    return render_template("achievements.html")

@app.route("/current")
def current():
    return render_template("current.html")

@app.route("/edit/<to_edit>", methods=["GET","POST","DELETE"])
def edit(to_edit):
    resol = Resolutions.query.filter_by(email=session["email"], resolution=to_edit).first()
    if flask.request.method == "POST":
        updated_resol = request.form
        if "set_active" in updated_resol:
            prev_active = Resolutions.query.filter_by(email=session["email"], active=1).first()
            prev_active.active = 0
            resol.active = 1
            db.session.commit()
        else:
            resol.resolution = updated_resol["name"]
            resol.time_frame = updated_resol["time-frame"]
            resol.progress_type = updated_resol["progress-visual"]
            db.session.commit()
        return redirect("/resolutions")
    else:
        return render_template("edit.html", resol=resol)

@app.route("/delete", methods=["GET","POST"])
def delete():
    resol = request.args.get("resol")  
    resol = Resolutions.query.filter_by(email=session["email"], resolution=resol).first()
    db.session.delete(resol)
    db.session.commit()
    return redirect("/resolutions")

@app.route("/new", methods=["GET","POST"])
def new():
    if "week" in request.form:
        all_ids = Resolutions.query.filter_by(email=session["email"], time_frame="week").all()
        if len(all_ids) == 0:
            return redirect("/resolutions")
        rand = randrange(len(all_ids) - 1)
        all_ids[rand].active = 1
    else:
        all_ids = Resolutions.query.filter_by(email=session["email"], time_frame="month").all()
        if len(all_ids) == 0:
            return redirect("/resolutions")
        rand = randrange(len(all_ids) - 1)
        all_ids[rand].active = 1
    db.session.commit()
    return redirect("/resolutions")

if __name__ == "__main__": 
    app.run(debug=True)