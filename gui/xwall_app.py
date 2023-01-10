import os
import re
import json
import socket
import subprocess
from flask import Flask, request, render_template, Blueprint
from flask_cors import CORS

# Get environment XWALL_PATH.
xwall_path = os.getenv('XWALL_PATH')
if not xwall_path:
    print('The xwall path is null, please set it by "export XWALL_PATH=xxx".')
else:
    print(f'The xwall path is ${xwall_path}/cli.')


app = Flask(__name__,
            template_folder="./dist",
            static_folder="./dist",
            static_url_path="")

home_page = Blueprint('index', __name__,
                       template_folder = './dist',
                       static_folder = './dist',
                       static_url_path="")

CORS(app, resources=r'/*')

# @app.route("/")
# def index():
#     return '<h1>Weclome to XWALL!</h1>'

# @home_page.route('/')
# def index():
#     return render_template('index.html')

# app.register_blueprint(home_page)

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/addrule", methods=['POST'])
def add_rule():
    data = request.json
    saddr = data['saddr'] if data and 'saddr' in data else None
    daddr = data['daddr'] if data and 'daddr' in data else None
    smask = data['smask'] if data and 'smask' in data else None
    dmask = data['dmask'] if data and 'dmask' in data else None
    protocol = data['protocol'] if data and 'protocol' in data else None
    sport_min = data['sport_min'] if data and 'sport_min' in data else None
    sport_max = data['sport_max'] if data and 'sport_max' in data else None
    dport_min = data['dport_min'] if data and 'dport_min' in data else None
    dport_max = data['dport_max'] if data and 'dport_max' in data else None
    action = data['action'] if data and 'action' in data else None
    logging = data['logging'] if data and 'logging' in data else None
    if saddr is None or daddr is None or smask is None or dmask is None or sport_min is None or sport_max is None or dport_min is None or dport_max is None or protocol is None or action is None or logging is None :
        return json.dumps({
            'code' :1,
            'msg': "missing args.",
        })
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -addrule {saddr} {daddr} {smask} {dmask} {sport_min} {sport_max} {dport_min} {dport_max} {protocol} {action} {logging}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': out,
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

@app.route("/delrule", methods=['GET'])
def del_rule():
    data = request.args
    idx = data['idx'] if data and 'idx' in data else None
    if idx is None :
        return json.dumps({
            'code' :1,
            'msg': "missing args.",
        })
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -delrule {idx}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': out,
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

@app.route("/readrule", methods=['GET'])
def read_rule():
    data = request.args
    start_idx = data.get('start_idx') if data and 'start_idx' in data else None
    end_idx = data.get('end_idx') if data and 'end_idx' in data else None
    if start_idx is None or end_idx is None :
        return json.dumps({
            'code' :1,
            'msg': "missing args.",
        })
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -readrule {start_idx} {end_idx} -json', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': json.loads(out),
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

@app.route("/saverule", methods=['GET'])
def save_rule():
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -saverule', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': out,
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

@app.route("/readlog", methods=['GET'])
def read_log():
    data = request.args
    start_idx = data.get('start_idx') if data and 'start_idx' in data else None
    end_idx = data.get('end_idx') if data and 'end_idx' in data else None
    if start_idx is None or end_idx is None :
        return json.dumps({
            'code' :1,
            'msg': "missing args.",
        })
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -readlog {start_idx} {end_idx} -json', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': json.loads(out),
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

@app.route("/clrlog", methods=['GET'])
def clr_log():
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -clrlog', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': out,
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

@app.route("/readmlog", methods=['GET'])
def read_mlog():
    data = request.args
    start_idx = data.get('start_idx') if data and 'start_idx' in data else None
    end_idx = data.get('end_idx') if data and 'end_idx' in data else None
    if start_idx is None or end_idx is None :
        return json.dumps({
            'code' :1,
            'msg': "missing args.",
        })
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -readmlog {start_idx} {end_idx} -json', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': json.loads(out),
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

@app.route("/clrmlog", methods=['GET'])
def clr_mlog():
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -clrmlog', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': out,
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

@app.route("/readconn", methods=['GET'])
def read_conn():
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -readconn -json', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': json.loads(out),
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

@app.route("/defact", methods=['POST'])
def def_act():
    data = request.json
    action = data['action'] if data and 'action' in data else None
    if action is None:
        return json.dumps({
            'code' :1,
            'msg': "missing args.",
        })
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -defact {action}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': out,
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

@app.route("/readdefact", methods=['GET'])
def read_def_act():
    r = subprocess.Popen(f'{xwall_path}/cli/xwall_app -readdefact', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = r.stdout.read().decode('utf8').strip()
    err = r.stderr.read().decode('utf8').strip()
    print(out)
    print(err)
    if err == '':
        return json.dumps({
            'code' :0,
            'msg': out,
        })
    else:
        return json.dumps({
            'code' :1,
            'msg': err,
        })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=11803)

    