import hmac
import hashlib
import subprocess
import os
import sys
from flask import Flask, request, jsonify
from dotenv import load_dotenv

app = Flask(__name__)

# ==========================================
# 1. SECURE CONFIGURATION (THE FIX)
# ==========================================

# Get the absolute path to the folder where THIS script lives
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Build the path to the .env file explicitly
dotenv_path = os.path.join(BASE_DIR, '.env')

# Load the environment variables
load_dotenv(dotenv_path)

# Fetch the Secret Token
GLOBAL_SECRET_TOKEN = os.getenv("GITHUB_SECRET")

# Debugging / Safety Check
print(f"📂 Loading configuration from: {dotenv_path}")
if not GLOBAL_SECRET_TOKEN:
    print("❌ CRITICAL ERROR: GITHUB_SECRET is missing or empty.")
    print("   Please check your .env file.")
    sys.exit(1) # Stop the server if no token exists
else:
    # Print first 5 chars only for safety
    print(f"✅ Security Token Loaded: {GLOBAL_SECRET_TOKEN[:5]}...")

# ==========================================
# 2. PROJECT MAPPING
# ==========================================

# NEW CONFIG STRUCTURE:
# Key = The endpoint name in the URL (e.g., /webhook/ecommerce)
# Value = A dictionary mapping BRANCH NAMES to SCRIPT PATHS
PROJECT_CONFIG = {
    "ecommerce": {
        "main": "/home/ubuntu/scripts/ecommerce_prod.sh",
        "dev":  "/home/ubuntu/scripts/ecommerce_dev.sh",
        "v2-beta": "/home/ubuntu/scripts/ecommerce_v2.sh"
    },
    "admin-panel": {
        "master": "/home/ubuntu/scripts/admin_prod.sh",
        "staging": "/home/ubuntu/scripts/admin_staging.sh"
    },
    # Simple project with only one branch? Just list that one.
    "test": {
        "main": "/root/automate_scripts/test.sh"
    },
    "pai_web_live": {
        "Live": "/root/automate_scripts/pai-web-live.sh",
        "Dev": "/root/automate_scripts/pai-web-dev.sh",
        "QA": "/root/automate_scripts/pai-web-qa.sh",
        "Beta": "/root/automate_scripts/pai-web-beta.sh"
    },
    "auto_deploy_script": {
        "main": "/root/automate_scripts/auto-deploy-script.sh"
    },
    "PAI_SMS": {
        "qa": "/root/automate_scripts/pai-sms-qa.sh",
        "Dev": "/root/automate_scripts/pai-sms-dev.sh"
    }
}

# ==========================================
# CORE LOGIC
# ==========================================

def verify_signature(req):
    signature = req.headers.get('X-Hub-Signature-256')
    if not signature:
        return False
    
    sha_name, signature = signature.split('=')
    if sha_name != 'sha256':
        return False
        
    mac = hmac.new(GLOBAL_SECRET_TOKEN.encode(), req.data, hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)

@app.route('/webhook/<project_key>', methods=['POST'])
def webhook_listener(project_key):
    # 1. SECURITY: Verify Token
    if not verify_signature(request):
        return jsonify({"msg": "Security verification failed"}), 403

    # 2. VALIDATION: Check if project endpoint exists
    project_branches = PROJECT_CONFIG.get(project_key)
    if not project_branches:
        return jsonify({"msg": f"Project '{project_key}' is not configured"}), 404

    # 3. IDENTIFY BRANCH
    # GitHub sends branch ref as "refs/heads/branch_name"
    payload = request.json
    ref = payload.get('ref', '')
    
    # Safety check: ensure it's a branch push, not a tag
    if 'refs/heads/' not in ref:
        return jsonify({"msg": "Not a branch push"}), 200

    current_branch = ref.split('/')[-1]

    # 4. LOOKUP SCRIPT FOR THIS SPECIFIC BRANCH
    script_path = project_branches.get(current_branch)

    if not script_path:
        # If we pushed to a branch that isn't configured (e.g., 'feature-login'), ignore it.
        return jsonify({"msg": f"No deployment script configured for branch: {current_branch}"}), 200

    # 5. CHECK FILE EXISTENCE
    if not os.path.isfile(script_path):
        return jsonify({"msg": f"Script missing on server: {script_path}"}), 500

    # 6. EXECUTE
    try:
        print(f"🚀 Deploying {project_key} [{current_branch}] via {script_path}...")
        
        result = subprocess.run(
            [script_path], 
            check=True, 
            shell=True,
            capture_output=True,
            text=True
        )
        
        print(f"✅ Success: {result.stdout}")
        return jsonify({
            "msg": "Deployment successful", 
            "project": project_key,
            "branch": current_branch,
            "logs": result.stdout
        }), 200

    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e.stderr}", file=sys.stderr)
        return jsonify({"msg": "Deployment failed", "error": e.stderr}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=7070)
