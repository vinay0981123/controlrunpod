import os, json, time
from flask import Flask, request, jsonify, redirect
import requests
from dotenv import load_dotenv
from flasgger import Swagger
import paramiko
from flask import Response

load_dotenv()

RUNPOD_BASE = os.getenv("RUNPOD_BASE", "https://rest.runpod.io/v1")
API_KEY = os.getenv("RUNPOD_API_KEY")
STATE_FILE = os.getenv("RUNPOD_STATE_FILE", "pod_state.json")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH")
SSH_USER = os.getenv("SSH_USER", "root")

DEFAULTS = {
    "cloudType": "SECURE",
    "name": os.getenv("POD_NAME", "stt-rtx4090-pod"),
    "imageName": os.getenv("IMAGE_NAME", "runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404"),
    "gpuCount": int(os.getenv("GPU_COUNT", "1")),
    "gpuTypeIds": [x.strip() for x in os.getenv("GPU_TYPE_IDS", "NVIDIA GeForce RTX 4090").split(",") if x.strip()],
    "dataCenterIds": [x.strip() for x in os.getenv("DATA_CENTER_IDS", "EUR-NO-1").split(",") if x.strip()],
    "gpuTypePriority": os.getenv("GPU_TYPE_PRIORITY", "availability"),
    "dataCenterPriority": os.getenv("DATA_CENTER_PRIORITY", "availability"),
    "interruptible": os.getenv("INTERRUPTIBLE", "false").lower() == "true",
    "ports": [x.strip() for x in os.getenv("PORTS", "22/tcp,8000/http").split(",") if x.strip()],
    "volumeInGb": int(os.getenv("VOLUME_IN_GB", "80")),
    "networkVolumeId": os.getenv("NETWORK_VOLUME_ID", None),
    "volumeMountPath": os.getenv("VOLUME_MOUNT_PATH", "/workspace"),
    "env": {
        "HF_TOKEN": os.getenv("HF_TOKEN", ""),
        "WHISPER_MODEL": os.getenv("WHISPER_MODEL", "large-v3"),
        "DEVICE": os.getenv("DEVICE", "cuda"),
        "HF_HOME": os.getenv("HF_HOME", "/workspace/.cache/huggingface"),
        "TRANSFORMERS_CACHE": os.getenv("TRANSFORMERS_CACHE", "/workspace/.cache/huggingface"),
        "TORCH_HOME": os.getenv("TORCH_HOME", "/workspace/.cache/torch"),
        "HUGGINGFACE_HUB_CACHE": os.getenv("HUGGINGFACE_HUB_CACHE", "/workspace/.cache/huggingface/hub"),
    }
}

app = Flask(__name__)
app.config["SWAGGER"] = {"title": "RunPod Orchestrator", "uiversion": 3}
swagger = Swagger(app)

def auth_headers():
    return {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json", "Accept": "application/json"}

def save_state(obj):
    with open(STATE_FILE, "w") as f:
        json.dump(obj, f, indent=2)

def load_state():
    if not os.path.exists(STATE_FILE):
        return None
    with open(STATE_FILE) as f:
        return json.load(f)




def ssh_tail(ip, port, file_path, lines=200):
    key = paramiko.Ed25519Key.from_private_key_file(SSH_KEY_PATH)
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(ip, port=port, username=SSH_USER, pkey=key, look_for_keys=False)
    try:
        cmd = f"if [ -f {file_path} ]; then tail -n {int(lines)} {file_path}; " \
              f"elif command -v journalctl >/dev/null 2>&1; then journalctl -n {int(lines)} --no-pager; " \
              f"elif command -v docker >/dev/null 2>&1; then docker logs --tail {int(lines)} $(hostname); " \
              f"else echo 'No known log source found. Provide ?path='; fi"
        _, stdout, stderr = cli.exec_command(cmd)
        out = stdout.read().decode()
        err = stderr.read().decode()
        code = stdout.channel.recv_exit_status()
        return code, out, err
    finally:
        cli.close()



def build_registry_auth():
    host = os.getenv("REGISTRY_HOST")
    user = os.getenv("REGISTRY_USERNAME")
    pwd  = os.getenv("REGISTRY_PASSWORD")
    if host and user and pwd:
        return {"registry": host, "username": user, "password": pwd}
    return None



@app.get("/pod-logs")
def pod_logs():
    st = load_state()
    if not st:
        return Response("No state found", status=400, content_type="text/plain")
    pod_id = st.get("id") or st.get("podId") or st.get("pod", {}).get("id")

    # Attempt REST logs if supported in your region
    url = f"{RUNPOD_BASE}/pods/{pod_id}/logs"
    r = requests.get(url, headers=auth_headers(), timeout=20)
    if r.status_code == 200 and r.text and r.text.strip() != "-- No entries --":
        return Response(r.content, status=200, content_type=r.headers.get("Content-Type", "text/plain"))

    # SSH fallback
    preferred_paths = [
        "/workspace/hearmefinal/uvicorn.log",
        "/workspace/hearmefinal/logs/app.log",
        "/workspace/logs/app.log"
    ]
    path = request.args.get("path") or preferred_paths[0]
    lines = int(request.args.get("lines") or 200)

    r2 = requests.get(f"{RUNPOD_BASE}/pods/{pod_id}", headers=auth_headers(), timeout=30)
    if r2.status_code >= 400:
        return Response(r2.text, status=r2.status_code, content_type="text/plain")
    pod = r2.json()
    ip = pod.get("publicIp")
    pm = pod.get("portMappings") or {}
    ssh_port = pm.get("22") if isinstance(pm, dict) else next((m.get("publicPort") for m in pm if str(m.get("privatePort")) == "22"), None)
    if not ip or not ssh_port:
        return Response("SSH not ready; cannot fetch logs via SSH", status=409, content_type="text/plain")

    code, out, err = ssh_tail(ip, ssh_port, path, lines)
    body = out if out else err
    return Response(body or "-- No entries --", status=200 if code == 0 else 500, content_type="text/plain")

@app.get("/")
def root():
    return redirect("/docs", code=302)

@app.get("/docs")
@app.get("/swagger")
def docs():
    return redirect("/apidocs", code=302)

@app.post("/create_pod")
def create_pod():
    """
    Create a new Pod (overwrites state file)
    ---
    consumes:
      - application/json
    responses:
      200:
        description: Created pod object
    """
    overrides = request.get_json(silent=True) or {}
    payload = {**DEFAULTS, **{k: v for k, v in overrides.items() if v is not None}}
    payload["env"] = {k: v for k, v in payload.get("env", {}).items() if v not in ("", None)}
    if not payload.get("networkVolumeId"):
        payload.pop("networkVolumeId", None)

    r = requests.post(f"{RUNPOD_BASE}/pods", headers=auth_headers(), json=payload, timeout=60)
    if r.status_code >= 400:
        return jsonify({"error": r.text, "status": r.status_code}), r.status_code
    pod = r.json()
    save_state(pod)
    return jsonify(pod), 200

@app.get("/get-ssh-command")
def get_ssh_command():
    st = load_state()
    if not st:
        return jsonify({"ready": False, "message": "No state found"}), 400
    pod_id = st.get("id") or st.get("podId") or st.get("pod", {}).get("id")

    r = requests.get(f"{RUNPOD_BASE}/pods/{pod_id}", headers=auth_headers(), timeout=30)
    if r.status_code >= 400:
        return jsonify({"ready": False, "message": r.text}), r.status_code
    pod = r.json()

    # Prefer proxy alias/username when available
    proxy_user = pod.get("sshUsername")
    if not proxy_user:
        hint = (pod.get("sshAlias") or pod.get("connectHint") or "")
        if "@ssh.runpod.io" in hint:
            proxy_user = hint.split("@")[0]

    if proxy_user:
        cmd = f"ssh {proxy_user}@ssh.runpod.io -i ~/.ssh/id_ed25519"
        return jsonify({"ready": True, "podId": pod_id, "sshCommand": cmd}), 200


    # Fallback: public IP + mapped port 22
    public_ip = pod.get("publicIp")
    pm = pod.get("portMappings") or {}
    ssh_port = pm.get("22") if isinstance(pm, dict) else next((m.get("publicPort") for m in pm if str(m.get("privatePort")) == "22"), None)
    if public_ip and ssh_port:
        cmd = f"ssh root@{public_ip} -p {ssh_port} -i ~/.ssh/id_ed25519"
        return jsonify({"ready": True, "podId": pod_id, "sshCommand": cmd, "mode": "public-ip"}), 200

    return jsonify({"ready": False, "message": "SSH proxy username and public IP not ready, retry shortly"}), 409


@app.get("/pods/count-running")
def count_running():
    """
    Return the number of RUNNING pods for this account.
    ---
    responses:
      200:
        description: Count of running pods
    """
    # Option A: filter server-side if supported
    r = requests.get(f"{RUNPOD_BASE}/pods?state=RUNNING", headers=auth_headers(), timeout=30)
    if r.status_code == 200:
        pods = r.json() if isinstance(r.json(), list) else r.json().get("items", [])
        return jsonify({"running": len(pods)}), 200

    # Option B: fallback to full list and client-side filter
    r = requests.get(f"{RUNPOD_BASE}/pods", headers=auth_headers(), timeout=30)
    if r.status_code >= 400:
        return jsonify({"error": r.text, "status": r.status_code}), r.status_code
    pods = r.json()
    # API may return list or {items: []}
    items = pods if isinstance(pods, list) else pods.get("items", [])
    running = [p for p in items if (p.get("runtime", {}).get("state") or p.get("status") or p.get("desiredStatus")) == "RUNNING"]
    return jsonify({"running": len(running)}), 200


@app.post("/pods/stop-all")
def stop_all():
    """
    Stop all RUNNING pods.
    ---
    responses:
      200:
        description: Stop results per pod
    """
    r = requests.get(f"{RUNPOD_BASE}/pods", headers=auth_headers(), timeout=30)
    if r.status_code >= 400:
        return jsonify({"error": r.text, "status": r.status_code}), r.status_code

    pods = r.json()
    items = pods if isinstance(pods, list) else pods.get("items", [])
    results = []
    for p in items:
        pid = p.get("id") or p.get("podId") or p.get("pod", {}).get("id")
        state = p.get("runtime", {}).get("state") or p.get("status") or p.get("desiredStatus")
        if not pid or state != "RUNNING":
            continue
        rr = requests.post(f"{RUNPOD_BASE}/pods/{pid}/stop", headers=auth_headers(), timeout=30)
        results.append({"id": pid, "status": rr.status_code, "body": safe_text(rr)})

    return jsonify({"stopped": results}), 200


@app.delete("/pods/terminate-all")
def terminate_all():
    """
    Terminate (delete) all pods (any state).
    ---
    responses:
      200:
        description: Termination results per pod
    """
    r = requests.get(f"{RUNPOD_BASE}/pods", headers=auth_headers(), timeout=30)
    if r.status_code >= 400:
        return jsonify({"error": r.text, "status": r.status_code}), r.status_code

    pods = r.json()
    items = pods if isinstance(pods, list) else pods.get("items", [])
    results = []
    for p in items:
        pid = p.get("id") or p.get("podId") or p.get("pod", {}).get("id")
        if not pid:
            continue
        rr = requests.delete(f"{RUNPOD_BASE}/pods/{pid}", headers=auth_headers(), timeout=30)
        results.append({"id": pid, "status": rr.status_code, "body": safe_text(rr)})

    return jsonify({"terminated": results}), 200


def safe_text(resp):
    try:
        return resp.json()
    except Exception:
        return resp.text


@app.get("/pod-status")
def pod_status():
    """
    Check if Pod is ready for SSH
    ---
    parameters:
      - name: id
        in: query
        required: false
        schema:
          type: string
    responses:
      200:
        description: Readiness message
    """
    pod_id = request.args.get("id")
    if not pod_id:
        st = load_state()
        if not st:
            return jsonify({"error": "No state found"}), 400
        pod_id = st.get("id") or st.get("podId") or st.get("pod", {}).get("id")

    r = requests.get(f"{RUNPOD_BASE}/pods/{pod_id}", headers=auth_headers(), timeout=30)
    if r.status_code >= 400:
        return jsonify({"error": r.text, "status": r.status_code}), r.status_code
    pod = r.json()

    # Ready if proxy username known, else if public IP + port 22 mapping exist
    proxy_user = pod.get("sshUsername") or (pod.get("sshAlias") or pod.get("connectHint") or "").split("@")[0]
    ready_proxy = bool(proxy_user)
    public_ip = pod.get("publicIp")
    pm = pod.get("portMappings") or {}
    ssh_port = pm.get("22") if isinstance(pm, dict) else next((m.get("publicPort") for m in pm if str(m.get("privatePort")) == "22"), None)
    ready_ip = bool(public_ip and ssh_port)

    if ready_proxy or ready_ip:
        return jsonify({"podId": pod_id, "ready": True, "message": "pod is ready for ssh"}), 200
    return jsonify({"podId": pod_id, "ready": False, "message": "pod is not ready for ssh"}), 200

@app.post("/stop")
def stop_pod():
    """
    Stop a pod (if eligible) [Note: pods with network volume in some modes may require terminate]
    ---
    parameters:
      - name: id
        in: query
        required: false
        schema:
          type: string
    responses:
      200:
        description: Stop response
    """
    pod_id = request.args.get("id")
    if not pod_id:
        st = load_state()
        if not st:
            return jsonify({"error": "No state found"}), 400
        pod_id = st.get("id") or st.get("podId") or st.get("pod", {}).get("id")
    r = requests.post(f"{RUNPOD_BASE}/pods/{pod_id}/stop", headers=auth_headers(), timeout=30)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})

@app.post("/start")
def start_pod():
    """
    Start or resume a pod
    ---
    parameters:
      - name: id
        in: query
        required: false
        schema:
          type: string
    responses:
      200:
        description: Start response
    """
    pod_id = request.args.get("id")
    if not pod_id:
        st = load_state()
        if not st:
            return jsonify({"error": "No state found"}), 400
        pod_id = st.get("id") or st.get("podId") or st.get("pod", {}).get("id")
    r = requests.post(f"{RUNPOD_BASE}/pods/{pod_id}/start", headers=auth_headers(), timeout=30)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})

@app.post("/terminate")
def terminate_pod():
    """
    Terminate (delete) a pod
    ---
    parameters:
      - name: id
        in: query
        required: false
        schema:
          type: string
    responses:
      200:
        description: Terminate response
    """
    pod_id = request.args.get("id")
    if not pod_id:
        st = load_state()
        if not st:
            return jsonify({"error": "No state found"}), 400
        pod_id = st.get("id") or st.get("podId") or st.get("pod", {}).get("id")
    r = requests.delete(f"{RUNPOD_BASE}/pods/{pod_id}", headers=auth_headers(), timeout=30)
    return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})

def ssh_exec(ip, port, commands):
    key = paramiko.Ed25519Key.from_private_key_file(SSH_KEY_PATH)
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(ip, port=port, username=SSH_USER, pkey=key, look_for_keys=False)
    try:
        joined = " && ".join(commands)
        _, stdout, stderr = cli.exec_command(joined)
        out = stdout.read().decode()
        err = stderr.read().decode()
        code = stdout.channel.recv_exit_status()
        return {"exit": code, "stdout": out, "stderr": err}
    finally:
        cli.close()

@app.post("/start_stt")
def start_stt():
    """
    Start STT on the pod via SSH
    ---
    tags: [control]
    summary: Launch uvicorn in background using the venv interpreter; prove venv is used and return logs path/PID.
    responses:
      200:
        description: Started and detached; returns checks, log path and PID file
      409:
        description: SSH not ready
      400:
        description: No state found
    """
    # Load latest pod id from state
    st = load_state()
    if not st:
        return jsonify({"error": "No state found"}), 400
    pod_id = st.get("id") or st.get("podId") or st.get("pod", {}).get("id")

    # Fetch pod for connection details
    r = requests.get(f"{RUNPOD_BASE}/pods/{pod_id}", headers=auth_headers(), timeout=30)
    if r.status_code >= 400:
        return jsonify({"error": r.text}), r.status_code
    pod = r.json()

    ip = pod.get("publicIp")
    pm = pod.get("portMappings") or {}
    if isinstance(pm, dict):
        ssh_port = pm.get("22")
    else:
        ssh_port = next((m.get("publicPort") for m in pm if str(m.get("privatePort")) == "22"), None)
    if not ip or not ssh_port:
        return jsonify({"ready": False, "message": "SSH not ready"}), 409

    # Build robust script to run remotely
    script = r"""#!/usr/bin/env bash
set -euo pipefail

# 1) Navigate to project
cd /workspace || { echo 'CHECK:cd_workspace=fail'; exit 2; }
echo 'CHECK:cd_workspace=ok'
cd /workspace/hearmefinal || { echo 'CHECK:cd_hearmefinal=fail'; exit 3; }
echo 'CHECK:cd_hearmefinal=ok'

# 2) Verify venv exists
if [ ! -x venv/bin/python3 ]; then
  echo 'CHECK:venv_missing=1'
  exit 10
fi
echo 'CHECK:venv_present=1'

# 3) Prove we’re using venv python
export VENV_PY="$(pwd)/venv/bin/python3"
echo "CHECK:which_python=$($VENV_PY -c 'import sys; print(sys.executable)')"
echo "CHECK:base_prefix=$($VENV_PY -c 'import sys; print(sys.base_prefix)')"
echo "CHECK:prefix=$($VENV_PY -c 'import sys; print(sys.prefix)')"

# 4) Start uvicorn in background and capture PID + logs
mkdir -p /workspace/hearmefinal/logs
nohup "$VENV_PY" -m uvicorn hearme.app:app \
  --host 0.0.0.0 --port 8000 \
  --log-level info --proxy-headers --forwarded-allow-ips='*' \
  > /workspace/hearmefinal/logs/uvicorn.log 2>&1 &

echo $! > /workspace/hearmefinal/logs/uvicorn.pid
echo 'CHECK:uvicorn_started=1'
echo 'CHECK:log_file=/workspace/hearmefinal/logs/uvicorn.log'
echo 'CHECK:pid_file=/workspace/hearmefinal/logs/uvicorn.pid'
echo 'CHECK:done=1'
"""

    # Encode and execute as a single remote command to avoid quoting issues
    import base64, json as _json
    b64 = base64.b64encode(script.encode()).decode()
    # Use Python on the remote to decode and pipe to bash; avoids shell -c pitfalls
    remote_cmd = f"python3 - <<'PY'\nimport base64,subprocess\ns=base64.b64decode('{b64}').decode()\nsubprocess.run(['bash','-s'],input=s.encode())\nPY\n"

    # IMPORTANT: pass a single command string to SSH so nothing is joined with '&&'
    result = ssh_exec(ip, ssh_port, [remote_cmd])

    # Parse CHECK markers from stdout
    checks = {}
    for line in (result.get("stdout") or "").splitlines():
        if line.startswith("CHECK:") and "=" in line:
            k, v = line.replace("CHECK:", "", 1).split("=", 1)
            checks[k.strip()] = v.strip()

    return jsonify({
        "podId": pod_id,
        "ready": True,
        "checks": checks,
        "result": result
    }), 200


if __name__ == "__main__":
    # Basic sanity checks so it doesn’t exit silently
    missing = []
    if not API_KEY:
        missing.append("RUNPOD_API_KEY")
    if not SSH_KEY_PATH or not os.path.exists(SSH_KEY_PATH):
        missing.append("SSH_KEY_PATH (file missing)")
    if missing:
        print("Missing required configuration:", ", ".join(missing))
        # Do not exit; you may still hit routes that don’t need SSH
    # Run Flask
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=True)
