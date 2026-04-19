"""
================================================================================
dashboard_v2/app_v2.py
ZenGuard — Live Pipeline War Room Server
Port: 5002

Serves the dashboard and streams live events via Server-Sent Events (SSE).
No database writes. Pure real-time push.
================================================================================
"""
import json, threading, queue, time, os
from datetime import datetime, timezone
from flask import Flask, Response, render_template, jsonify, request
from flask_cors import CORS

# Bootstrap simulator (must be importable from this location)
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from simulator import SIM, run_simulation

app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)),
            static_url_path="")
CORS(app)

# ── Serve the war room UI ────────────────────────────────────────────────────
@app.route("/")
def index():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index_v2.html")
    with open(html_path, encoding="utf-8") as f:
        return f.read(), 200, {"Content-Type": "text/html"}


# ── SSE Stream ───────────────────────────────────────────────────────────────
def event_stream(client_queue: queue.Queue):
    """Generator that yields SSE-formatted data strings."""
    # Send history first so new clients see the last 200 events immediately
    with SIM.lock:
        catchup = list(SIM.history)
    for env in catchup:
        yield f"data: {json.dumps(env)}\n\n"

    while True:
        try:
            envelope = client_queue.get(timeout=30)
            yield f"data: {json.dumps(envelope)}\n\n"
        except queue.Empty:
            yield ": heartbeat\n\n"  # keep-alive ping

@app.route("/api/stream")
def stream():
    client_q = queue.Queue(maxsize=500)
    with SIM.lock:
        SIM.subscribers.append(client_q)

    def cleanup():
        with SIM.lock:
            if client_q in SIM.subscribers:
                SIM.subscribers.remove(client_q)

    def generate():
        try:
            yield from event_stream(client_q)
        finally:
            cleanup()

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── Status API ───────────────────────────────────────────────────────────────
@app.route("/api/status")
def status():
    return jsonify({
        "running":        SIM.running,
        "paused":         SIM.paused,
        "current_file":   SIM.current_file,
        "current_scenario": SIM.current_scenario,
        "events_total":   SIM.events_total,
        "attacks_total":  SIM.attacks_total,
        "soar_actions":   SIM.soar_actions,
        "speed_factor":   SIM.speed_factor,
        "subscribers":    len(SIM.subscribers),
    })

# ── Control API ───────────────────────────────────────────────────────────────
@app.route("/api/control", methods=["POST"])
def control():
    action = request.json.get("action", "")
    if action == "pause":
        SIM.paused = True
    elif action == "resume":
        SIM.paused = False
    elif action == "speed":
        SIM.speed_factor = float(request.json.get("value", 1.0))
    elif action == "restart":
        SIM.running  = False
        SIM.paused   = False
        time.sleep(0.5)
        thread = threading.Thread(target=run_simulation, daemon=True)
        thread.start()
    return jsonify({"ok": True, "action": action})


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Starting ZenGuard Live War Room on http://localhost:5002")
    print("[*] Launching simulation thread...")
    sim_thread = threading.Thread(target=run_simulation, daemon=True)
    sim_thread.start()
    app.run(host="0.0.0.0", port=5002, debug=False, threaded=True)
