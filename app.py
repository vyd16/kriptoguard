import os
import uuid
import base64
import zipfile
import shutil
import tempfile
from flask import Flask, render_template, request, jsonify, Response, send_file
from werkzeug.utils import secure_filename
from encryption import (
    encrypt_file_stream, 
    decrypt_file_stream, 
    encrypt_text, 
    decrypt_text,
    MAGIC_FILE,
    MAGIC_TEXT
)

app = Flask(__name__)

@app.after_request
def add_header(r):
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    return r

# Temporary directory for file processing (located outside project path to prevent Flask reload loops)
TEMP_DIR = os.path.join(tempfile.gettempdir(), "kriptoguard_temp")
os.makedirs(TEMP_DIR, exist_ok=True)

# Clean up any leftover temp files on startup
def cleanup_temp_dir():
    try:
        if os.path.exists(TEMP_DIR):
            shutil.rmtree(TEMP_DIR)
        os.makedirs(TEMP_DIR, exist_ok=True)
    except Exception as e:
        print(f"Error cleaning temp directory: {e}")

cleanup_temp_dir()

# --- Page Routes ---

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/text')
def enkrip_text():
    return render_template('enkriptext.html')

@app.route('/file')
def enkrip_file():
    return render_template('enkripfile.html')

# --- Key Generation API ---

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    """
    Generates a secure 32-byte key file and returns it as a download.
    """
    key_bytes = os.urandom(32)
    
    # Save key to temporary file
    filename = "kriptoguard.key"
    temp_path = os.path.join(TEMP_DIR, f"{uuid.uuid4()}.key")
    
    with open(temp_path, 'wb') as f:
        f.write(key_bytes)
        
    return send_file(
        temp_path,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=filename
    )

# --- Text Cryptography API ---

@app.route('/api/encrypt-text', methods=['POST'])
def api_encrypt_text():
    try:
        data = request.json or {}
        text = data.get('text', '')
        password = data.get('password', '')
        keyfile_b64 = data.get('keyfile', '')

        if not text:
            return jsonify({"status": "error", "message": "Teks sumber tidak boleh kosong."}), 400

        keyfile_bytes = None
        if keyfile_b64:
            if ',' in keyfile_b64:
                keyfile_b64 = keyfile_b64.split(',')[1]
            keyfile_bytes = base64.b64decode(keyfile_b64)

        if not password and not keyfile_bytes:
            return jsonify({"status": "error", "message": "Masukkan password atau unggah file kunci (.key)."}), 400

        encrypted_bytes = encrypt_text(text, password, keyfile_bytes)
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')

        return jsonify({"status": "success", "result": encrypted_b64})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/decrypt-text', methods=['POST'])
def api_decrypt_text():
    try:
        data = request.json or {}
        ciphertext_b64 = data.get('ciphertext', '')
        password = data.get('password', '')
        keyfile_b64 = data.get('keyfile', '')

        if not ciphertext_b64:
            return jsonify({"status": "error", "message": "Teks terenkripsi tidak boleh kosong."}), 400

        keyfile_bytes = None
        if keyfile_b64:
            if ',' in keyfile_b64:
                keyfile_b64 = keyfile_b64.split(',')[1]
            keyfile_bytes = base64.b64decode(keyfile_b64)

        try:
            encrypted_bytes = base64.b64decode(ciphertext_b64)
        except Exception:
            return jsonify({"status": "error", "message": "Format base64 teks terenkripsi tidak valid."}), 400

        decrypted_str = decrypt_text(encrypted_bytes, password, keyfile_bytes)
        return jsonify({"status": "success", "result": decrypted_str})
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Terjadi kesalahan: {str(e)}"}), 500

# --- File Cryptography API ---

import time

def cleanup_old_temp_files():
    """
    Deletes temporary files in TEMP_DIR that are older than 2 minutes.
    """
    try:
        now = time.time()
        for filename in os.listdir(TEMP_DIR):
            file_path = os.path.join(TEMP_DIR, filename)
            if os.path.isfile(file_path):
                if now - os.path.getmtime(file_path) > 120:
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass
    except Exception as e:
        print(f"Error during temp file cleanup: {e}")

@app.route('/api/encrypt-file', methods=['POST'])
def api_encrypt_file():
    cleanup_old_temp_files()
    temp_input = None
    temp_output = None
    try:
        # Retrieve configuration
        password = request.form.get('password', '')
        zip_compression = request.form.get('zip_compression', 'false') == 'true'
        
        # Read Key File if uploaded
        keyfile_bytes = None
        if 'keyfile' in request.files:
            kf = request.files['keyfile']
            if kf.filename:
                keyfile_bytes = kf.read()

        if not password and not keyfile_bytes:
            return jsonify({"status": "error", "message": "Masukkan kata sandi atau file kunci (.key)."}), 400

        # Read uploaded files
        uploaded_files = request.files.getlist('files[]')
        if not uploaded_files or (len(uploaded_files) == 1 and uploaded_files[0].filename == ''):
            return jsonify({"status": "error", "message": "Tidak ada file yang diunggah."}), 400

        # Unique session ID for temp files
        session_id = str(uuid.uuid4())

        # If multiple files OR zip compression checked, zip them first
        if len(uploaded_files) > 1 or zip_compression:
            temp_zip_path = os.path.join(TEMP_DIR, f"{session_id}_archive.zip")
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for f in uploaded_files:
                    if f.filename:
                        safe_name = secure_filename(f.filename)
                        # Save temporarily to add to zip
                        temp_f_path = os.path.join(TEMP_DIR, f"{session_id}_{safe_name}")
                        f.save(temp_f_path)
                        zip_file.write(temp_f_path, safe_name)
                        os.remove(temp_f_path)
            
            temp_input = temp_zip_path
            original_filename = "kriptoguard_archive.zip"
        else:
            # Single file, no zip
            f = uploaded_files[0]
            safe_name = secure_filename(f.filename)
            temp_input = os.path.join(TEMP_DIR, f"{session_id}_{safe_name}")
            f.save(temp_input)
            original_filename = safe_name

        # Destination encrypted file (using unique ID for final download link)
        download_id = str(uuid.uuid4())
        temp_output = os.path.join(TEMP_DIR, f"{download_id}.dat")
        
        # Perform encryption
        encrypt_file_stream(temp_input, temp_output, password, keyfile_bytes)
        
        # Remove input file immediately
        os.remove(temp_input)
        temp_input = None

        download_name = f"{original_filename}.enc"
        return jsonify({
            "status": "success",
            "download_url": f"/api/download/{download_id}?filename={secure_filename(download_name)}"
        })

    except Exception as e:
        # Cleanup on failure
        if temp_input and os.path.exists(temp_input):
            os.remove(temp_input)
        if temp_output and os.path.exists(temp_output):
            os.remove(temp_output)
        return jsonify({"status": "error", "message": f"Enkripsi gagal: {str(e)}"}), 500

@app.route('/api/decrypt-file', methods=['POST'])
def api_decrypt_file():
    cleanup_old_temp_files()
    temp_input = None
    temp_output = None
    try:
        password = request.form.get('password', '')
        
        # Read Key File if uploaded
        keyfile_bytes = None
        if 'keyfile' in request.files:
            kf = request.files['keyfile']
            if kf.filename:
                keyfile_bytes = kf.read()

        # Read encrypted file
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "Tidak ada file yang diunggah."}), 400
        
        uploaded_file = request.files['file']
        if not uploaded_file or uploaded_file.filename == '':
            return jsonify({"status": "error", "message": "Tidak ada file yang dipilih."}), 400

        session_id = str(uuid.uuid4())
        safe_name = secure_filename(uploaded_file.filename)
        
        temp_input = os.path.join(TEMP_DIR, f"{session_id}_{safe_name}")
        uploaded_file.save(temp_input)

        # Output path (using unique ID for final download link)
        download_id = str(uuid.uuid4())
        temp_output = os.path.join(TEMP_DIR, f"{download_id}.dat")

        # Perform decryption
        decrypt_file_stream(temp_input, temp_output, password, keyfile_bytes)

        # Remove input file immediately
        os.remove(temp_input)
        temp_input = None

        # Determine download name
        if safe_name.lower().endswith('.enc'):
            download_name = safe_name[:-4]
        else:
            download_name = "kriptoguard_decrypted"

        # Auto-detect if decrypted output is a zip archive, and force .zip extension
        if zipfile.is_zipfile(temp_output):
            if not download_name.lower().endswith('.zip'):
                download_name = download_name + ".zip"

        return jsonify({
            "status": "success",
            "download_url": f"/api/download/{download_id}?filename={secure_filename(download_name)}"
        })

    except ValueError as e:
        # User-friendly errors (incorrect password/tampered file)
        if temp_input and os.path.exists(temp_input):
            os.remove(temp_input)
        if temp_output and os.path.exists(temp_output):
            os.remove(temp_output)
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        # Generic errors
        if temp_input and os.path.exists(temp_input):
            os.remove(temp_input)
        if temp_output and os.path.exists(temp_output):
            os.remove(temp_output)
        return jsonify({"status": "error", "message": f"Dekripsi gagal: {str(e)}"}), 500

@app.route('/api/download/<file_id>', methods=['GET'])
def api_download(file_id):
    cleanup_old_temp_files()
    filename = request.args.get('filename', 'download')
    # Validate UUID format to prevent directory traversal
    try:
        uuid.UUID(file_id)
    except ValueError:
        return "Invalid File ID", 400

    file_path = os.path.join(TEMP_DIR, f"{file_id}.dat")
    if not os.path.exists(file_path):
        return "File not found or already downloaded", 404

    # Prevent caching and stream the file
    response = send_file(file_path, as_attachment=True, download_name=filename)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5000)
