from pymongo import MongoClient
import datetime
import jwt

SECRET_KEY='N@\xc4\x1bC\xb7\xd0\xbc\xb4\tA\xd9\xcb\x13I?\x92\x104\x1b\xaa\xdc}\xca'

def signup(data):
  client=MongoClient("127.0.0.1",27017,maxPoolSize=None)
  db=client.kolam
  dicte=data
  existing_doc=db.login.find_one({"email":dicte["email"]})
  client.close()
  if not existing_doc:
    result=db.login.insert(dicte)
    if result:
      return "Inserted successfully"
    else:
      return "Try later"
  else:
     return "data already present"

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

def decode_refresh_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, SECRET_KEY)
        return ({'sub':payload['sub']})
    except jwt.ExpiredSignatureError:
        return ({'status':'failed','msg':'Signature expired. Please log in again.'})
    except jwt.InvalidTokenError:
        return ({'status':'failed','msg':'Invalid token. Please log in again.'})

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
        return ({'sub':payload['sub']})
    except jwt.ExpiredSignatureError:
        return ({'status':'failed','msg':'Signature expired. Please log in again.'})
    except jwt.InvalidTokenError:
        return ({'status':'failed','msg':'Invalid token. Please log in again.'})


def login(data):
  client=MongoClient("127.0.0.1",27017,maxPoolSize=None)
  db=client.kolam
  dicte=data
  keys=dicte.keys()
  keys=sorted(keys)
  k=["email","password"]
  if(keys==k):
    existing_doc=db.login.find_one(dicte)
    client.close()
    if existing_doc:
      return({'status':"Succesfull",'access_token':encode_auth_token(dicte['email']),'data_profile':existing_doc,'refresh_id':refresh_id(dicte['email'])})
    else:
      return("Invalid")
  else:
    return("Invalid")

def validate_user(data):
  client=MongoClient("127.0.0.1",27017,maxPoolSize=None)
  db=client.kolam
  d=db.login.find_one(data)
  client.close()
  response={}
  if d:
    response["status"]="valid"
    return response
  else:
    return "invalid"

def profile_details(query):
  client=MongoClient("127.0.0.1",27017,maxPoolSize=None)
  db=client.kolam
  access_token=query['access_token']
  dicte=decode_auth_token(access_token)
  print dicte
  if 'status' in dicte:
    return dicte
  else:
    data={}
    data['username']=dicte['sub']
    existing_doc = db.login.find_one(data,{'_id':False})
    client.close()
    if existing_doc:
      existing_doc['new_token']=encode_auth_token(data['username'])
      return existing_doc
    else:
      return 'Data not found for this user'
  
