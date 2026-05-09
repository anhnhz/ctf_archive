import os
import uuid
import subprocess
from flask import Flask, request, jsonify, render_template, send_from_directory, url_for
from multi import MultiFileHandler
import bleach
import random

app = Flask(__name__)

UPLOAD_DIR = "upload"
REPORT_DIR = "report"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

file_handler = MultiFileHandler(upload_dir=UPLOAD_DIR)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET'])
def scan_page():
    return render_template('scan.html')

@app.route('/report', methods=['GET'])
def report_page():
    return render_template('report.html')

@app.route('/reports', methods=['GET'])
def reports_page():
    files = []
    for fname in os.listdir(REPORT_DIR):
        if fname.startswith("report_") and fname.endswith(".html"):
            path = os.path.join(REPORT_DIR, fname)
            files.append({
                "name": fname,
                "url": url_for('serve_notes', filename=fname),
                "mtime": os.path.getmtime(path)
            })
    files.sort(key=lambda x: x["mtime"], reverse=True)
    return render_template('reports.html', notes=files)

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    sanitized_filename = file_handler._sanitize_filename(file.filename)
    file_path = os.path.join(UPLOAD_DIR, sanitized_filename)

    try:
        file.save(file_path)
        scan_results = file_handler.process_uploaded_files([file_path])
        
        summary = scan_results['scan_summary']
        threat_info = scan_results['threat_summary']
        
        if summary['malicious_files'] > 0:
            return jsonify({
                "status": "MALICIOUS",
                "message": "THREAT DETECTED",
                "scan_summary": {
                    "threats_found": summary['malicious_files'],
                    "suspicious_files": summary['suspicious_files'],
                    "risk_level": threat_info['risk_level'],
                    "scan_time": f"{summary['scan_time']}s"
                },
                "threats": threat_info['threats_detected'],
                "recommendations": threat_info['recommendations'],
                "detailed_results": scan_results
            }), 200
        elif summary['suspicious_files'] > 0:
            return jsonify({
                "status": "SUSPICIOUS", 
                "message": "POTENTIALLY UNSAFE",
                "scan_summary": {
                    "suspicious_files": summary['suspicious_files'],
                    "risk_level": threat_info['risk_level'],
                    "scan_time": f"{summary['scan_time']}s"
                },
                "warnings": threat_info['threats_detected'],
                "recommendations": threat_info['recommendations'],
                "detailed_results": scan_results
            }), 200
        else:
            return jsonify({
                "status": "CLEAN",
                "message": "FILE IS SAFE", 
                "scan_summary": {
                    "clean_files": summary['clean_files'],
                    "risk_level": threat_info['risk_level'],
                    "scan_time": f"{summary['scan_time']}s",
                    "scanner_version": summary['scanner_version']
                },
                "file_info": scan_results['file_results'][0]['file_info'] if scan_results['file_results'] else {},
                "detailed_results": scan_results
            }), 200
            
    except Exception as e:
        return jsonify({
            "status": "ERROR",
            "message": "SCAN ERROR",
            "error": str(e),
            "recommendations": ["Please try uploading the file again", "Contact support if problem persists"]
        }), 500

@app.route('/submit-report', methods=['POST'])
def submit_report():
    data = request.get_json()
    if not data or 'note' not in data:
        return jsonify({"error": "No report provided"}), 400

    cleaned_note = bleach.clean(data['note'])

    note_id = str(random.getrandbits(32))
    filename = f"report_{note_id}.html"
    filepath = os.path.join(REPORT_DIR, filename)

    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(cleaned_note)
  
    url = f"http://localhost:5000/{REPORT_DIR}/{filename}"

    try:
        subprocess.run(["python3", "bot.py", url], check=True)
    except Exception as e:
        return jsonify({"error": "Failed to review", "details": str(e)}), 500

    return jsonify({"message": "Report uploaded and bot triggered", "report_url": url}), 200

@app.route('/report/<path:filename>')
def serve_notes(filename):
    return send_from_directory(REPORT_DIR, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
