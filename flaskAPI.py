from flask import Flask,jsonify,make_response,request
from flask_sqlalchemy import SQLAlchemy
import jwt
from pymongo import MongoClient
import datetime
from functools import wraps
import os

app = Flask(__name__)

# 'mysql://testuser:test123@68.183.90.163/testdb'
app.config['SECRET_KEY'] = '####$$$$'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('mySQL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class userClass(db.Model):
    __tablename__ = 'tbl_users'
    id = db.Column(db.Integer, primary_key = True)
    display_name = db.Column(db.String(50))
    email_id = db.Column(db.String(50))
    mac_address = db.Column(db.String(50))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            if data['flag']:
                clbk = True
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(clbk, *args, **kwargs)

    return decorated


@app.route('/users',methods=['GET'])
@token_required
def allUser(userToken):
    users = userClass.query.all()[:10]
    result = []

    for user in users:
        row={}
        row['displayName'] = user.display_name
        row['emailID'] = user.email_id
        row['id']=user.id
        row['mac'] = user.mac_address
        result.append(row)
    return jsonify({'user':result})

@app.route('/login')
def login():
    
    auth = request.authorization

    client = MongoClient(os.environ['mongoURI'])
    db = client.apiUser
    collection = db.users

    clbk  = collection.find({'name':auth.username})    
    rslt = [i for i in clbk]
    print(rslt,clbk.count(),auth.username)
    if len(rslt)==0:
        return jsonify({'message':'Invalid user'})
    if clbk:
        token = jwt.encode({'flag' : rslt[0]['flag'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

    return jsonify({'token' : token.decode('UTF-8')})


if __name__ == '__main__':
    app.run(debug=True)