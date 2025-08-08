from flask import Flask 
from flask import Flask, request, jsonify
from pathlib import Path
from datetime import datetime
import uuid
import os

STORAGE_DIR = Path("storage")

app= Flask(__name__)

@app.route("/")
def index():
	return "Server is ready and listening, woke up."

@app.route("/health", methods=["GET"])
def health():
	return jsonify({"status": "ok its healthy"})

@app.route("/upload", methods=["POST"])
def upload():
	if "file" not in request.files:
		return jsonify({"error":"No file given in argument!"},400)
	
	file=request.files["file"]
	name=file.filename
	if name == "":
		return jsonify({"error":"Wrong file name format!"}, 400)
	save_path=STORAGE_DIR/name
	file.save(save_path)
	# ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    # unique_name = f"{ts}_{uuid.uuid4().hex}_{file.filename}"
	return jsonify({"message": "File uploaded successfully", "saved_as": name}), 200

if __name__=="__main__":
	print("[*] Starting server on 0.0.0.0:8080")
	app.run(host="0.0.0.0", port=8080)

