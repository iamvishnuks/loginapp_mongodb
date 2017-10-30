import datetime

import MySQLdb
import jwt
from pymongo import MongoClient

SECRET_KEY = 'N@\xc4\x1bC\xb7\xd0\xbc\xb4\tA\xd9\xcb\x13I?\x92\x104\x1b\xaa\xdc}\xca'

def refresh_id(user_id):
    """
    Generates the Refresh ID
    :return: string
    """
    try:
        payload = {
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            SECRET_KEY,
            algorithm='HS256'
        )
    except Exception as e:
        return e


def signup(data):
    client = MongoClient("127.0.0.1", 27017, maxPoolSize=None)
    mongodb = client.kolam
    dicte = data
    existing_doc = mongodb.login.find_one({"email": dicte["email"]})
    if not existing_doc:
        result = 0
        mysql = MySQLdb.connect("localhost", "root", "vishnuks", "refresh_tokens")
        cursor = mysql.cursor()
        try:
            cursor.execute("insert into refresh_ids(user,token,is_delete) values(%s,%s,%s)",
                           (dicte['email'], refresh_id(dicte['email']), 0))
            mysql.commit()
            mysql.close()
            result = mongodb.login.insert(dicte)
            client.close()
        except Exception as e:
            mysql.rollback()
            mysql.close()
            print "Unsuccessful  while adding refresh tokens :", e, len(refresh_id(dicte['email']))
        finally:
            if result:
                return "Inserted successfully"
            else:
                return "Try later"
    else:
        return "data already present"


def logout(token):
    user = decode_refresh_token(token)
    user = user['sub']
    mysql = MySQLdb.connect("localhost", "root", "vishnuks", "refresh_tokens")
    cursor = mysql.cursor()
    cmd = "update refresh_ids set is_delete=TRUE where user='" + user + "'"
    try:
        cursor.execute(cmd)
        mysql.commit()
        mysql.close()
        return ({'status': 'True', 'response': 'logged out'})
    except Exception as e:
        mysql.rollback()
        mysql.close()
        print "Here is an error: ", e
        return ({'status': 'False', 'response': 'Something went wrong'})


def decode_refresh_token(refresh_token):
    """
    Decodes the refresh token and generates a access token
    :param refresh_token:
    :return: integer|string
    """
    client = MongoClient("127.0.0.1", 27017, maxPoolSize=None)
    db = client.kolam
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY)
        user = payload['sub']
        mysql = MySQLdb.connect("localhost", "root", "vishnuks", "refresh_tokens")
        cursor = mysql.cursor()
        result = cursor.execute("select user from refresh_ids where user='" + user + "' and is_delete=1")
        print result
        if result:
            return ({'Message': "You are already logged out. Please login again with your credentials to continue",
                     'response': 'False'})
        else:
            access_token = encode_auth_token(user)
            return ({'Message': "Successful", "access_token": access_token, "status": 'True'})
    except jwt.ExpiredSignatureError:
        return ({'status': 'failed', 'msg': 'Signature expired. Please log in again.'})
    except jwt.InvalidTokenError:
        return ({'status': 'failed', 'msg': 'Invalid token. Please log in again.'})


def encode_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=60),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            SECRET_KEY,
            algorithm='HS256'
        )
    except Exception as e:
        return e


def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, SECRET_KEY)
        return ({'sub': payload['sub']})
    except jwt.ExpiredSignatureError:
        return ({'status': 'failed', 'msg': 'Signature expired. Please log in again.'})
    except jwt.InvalidTokenError:
        return ({'status': 'failed', 'msg': 'Invalid token. Please log in again.'})


def login(data):
    client = MongoClient("127.0.0.1", 27017, maxPoolSize=None)
    db = client.kolam
    dicte = data
    keys = dicte.keys()
    keys = sorted(keys)
    k = ["email", "password"]
    if (keys == k):
        existing_doc = db.login.find_one(dicte)
        client.close()
        if existing_doc:
            return (
                {'status': "Succesfull", 'access_token': encode_auth_token(dicte['email']),
                 'data_profile': existing_doc,
                 'refresh_id': refresh_id(dicte['email'])})
        else:
            return ("Invalid")
    else:
        return ("Invalid")


def validate_user(data):
    client = MongoClient("127.0.0.1", 27017, maxPoolSize=None)
    db = client.kolam
    d = db.login.find_one(data)
    client.close()
    response = {}
    if d:
        response["status"] = "valid"
        return response
    else:
        return "invalid"


def profile_details(query):
    client = MongoClient("127.0.0.1", 27017, maxPoolSize=None)
    db = client.kolam
    access_token = query['access_token']
    dicte = decode_auth_token(access_token)
    print dicte
    if 'status' in dicte:
        return dicte
    else:
        data = {}
        data['username'] = dicte['sub']
        existing_doc = db.login.find_one(data, {'_id': False})
        client.close()
        if existing_doc:
            existing_doc['new_token'] = encode_auth_token(data['username'])
            return existing_doc
        else:
            return 'Data not found for this user'
