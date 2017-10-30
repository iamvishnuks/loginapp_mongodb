import ast
import json

from flask import Flask, request, abort, jsonify
from flask_cors import CORS

from login_register import signup, login, validate_user, logout, profile_details, decode_refresh_token

app = Flask(__name__)
app.secret_key = 'N@\xc4\x1bC\xb7\xd0\xbc\xb4\tA\xd9\xcb\x13I?\x92\x104\x1b\xaa\xdc}\xca'
CORS(app)


@app.route('/')
def hello_world():
    return 'Hi!'


@app.route('/refresh/', methods=['POST'])
def get_refresh_response():
    if not request.json or 'refresh_token' not in request.json:
        print request.json
        abort(400)
    data = {}
    refresh_token = request.json['refresh_token']
    data['response'] = decode_refresh_token(refresh_token)
    return jsonify(data)


@app.route('/logout/', methods=['POST'])
def get_logout_response():
    if not request.json or 'refresh_token' not in request.json:
        abort(400)
    response = logout(request.json['refresh_token'])
    return jsonify(response)


@app.route('/signup/', methods=['POST'])
def get_signup_response():
    k = ('username', 'password', 'dob', 'name', 'lat', 'lon', 'email', 'language', 'tob', 'gender', 'pob')
    if not request.json or not all(i in request.json for i in k):
        abort(400)
    data = {}
    query = {}
    print request.json
    query["username"] = request.json['username']
    query["password"] = request.json['password']
    query["dob"] = request.json['dob']
    query["name"] = request.json['name']
    query["lat"] = request.json['lat']
    query["lon"] = request.json['lon']
    query["email"] = request.json['email']
    query["language"] = request.json['language']
    query["tob"] = request.json['tob']
    query["gender"] = request.json['gender']
    query["pob"] = request.json['pob']
    data['response'] = signup(query)
    json_data = json.dumps(data)
    return (json_data), 201


@app.route('/login/', methods=['POST'])
def get_login_response():
    if not request.json or 'email' not in request.json:
        abort(400)
    data = {}
    query = {}
    query['email'] = request.json['email']
    query['password'] = request.json['password']
    data['response'] = login(query)
    print data['response']
    if data['response'] == 'Invalid':
        return jsonify(data)
    del data['response']['data_profile']['_id']
    json_data = jsonify(data)
    return (json_data), 201


@app.route("/validate_user/<string:query>")
def get_validate_response(query):
    data = ast.literal_eval(query)
    dicte = {}
    dicte["response"] = validate_user(data)
    json_data = jsonify(dicte)
    return (json_data)


@app.route('/profile/', methods=['POST'])
def profile():
    if not request.json or 'access_token' not in request.json:
        print request.json
        abort(400)
    data = {}
    query = {}
    query['access_token'] = request.json['access_token']
    data['response'] = profile_details(query)
    json_data = jsonify(data)
    return json_data


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
