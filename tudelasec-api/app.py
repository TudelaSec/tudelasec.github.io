import os
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "TudelaSec API Proxy Online", "version": "2.0"})

# --- 1. SHODAN ---
@app.route('/api/osint/shodan', methods=['GET'])
def shodan_lookup():
    target_ip = request.args.get('ip')
    if not target_ip: return jsonify({"error": "Falta IP"}), 400
    
    api_key = os.getenv('SHODAN_API_KEY')
    url = f"https://api.shodan.io/shodan/host/{target_ip}?key={api_key}"
    
    try:
        r = requests.get(url)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- 2. HUNTER.IO ---
@app.route('/api/osint/hunter', methods=['GET'])
def hunter_lookup():
    domain = request.args.get('domain')
    if not domain: return jsonify({"error": "Falta dominio"}), 400
    
    api_key = os.getenv('HUNTER_API_KEY')
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    
    try:
        r = requests.get(url)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- 3. VIRUSTOTAL ---
@app.route('/api/osint/vt', methods=['GET'])
def vt_lookup():
    file_hash = request.args.get('hash')
    if not file_hash: return jsonify({"error": "Falta hash"}), 400
    
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    # VirusTotal usa headers para la autenticacion, no la URL
    headers = {"x-apikey": api_key}
    
    try:
        r = requests.get(url, headers=headers)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
