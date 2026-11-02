
from flask import Blueprint, render_template, request
from werkzeug.utils import secure_filename
from pathlib import Path
import tempfile

from .url_analyser import analyze_url
from .malware_analyser import analyze_file

main = Blueprint("main", __name__)

MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB


@main.route("/", methods=["GET"])
def homepage():
    return render_template("index.html")


@main.route("/analyze_url", methods=["POST"])
def analyze_url_route():
    url = request.form.get("url", "").strip()

    if not url:
        result = {
            "risk": "Invalid",
            "reasons": ["Please enter a URL."]
        }
    else:
        risk, reasons = analyze_url(url)
        result = {
            "risk": risk,
            "reasons": reasons
        }

    return render_template(
        "index.html",
        analysis=result,
        input_url=url
    )


@main.route("/analyze_file", methods=["POST"])
def analyze_file_route():
    uploaded_file = request.files.get("file")

    if not uploaded_file or not uploaded_file.filename:
        result = {
            "status": "Invalid",
            "message": "Please select a file to analyse.",
            "details": []
        }
        return render_template("index.html", malware_analysis=result)

    filename = secure_filename(uploaded_file.filename)

    if not filename:
        result = {
            "status": "Invalid",
            "message": "The uploaded filename is invalid.",
            "details": []
        }
        return render_template("index.html", malware_analysis=result)

    # Reject oversized requests before saving the upload.
    if (
        request.content_length is not None
        and request.content_length > MAX_UPLOAD_SIZE + 1024 * 1024
    ):
        result = {
            "status": "Invalid",
            "message": "The upload is too large. Maximum file size is 100 MB.",
            "details": []
        }
        return render_template("index.html", malware_analysis=result)

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / filename
            uploaded_file.save(file_path)

            if file_path.stat().st_size > MAX_UPLOAD_SIZE:
                result = {
                    "status": "Invalid",
                    "message": "The file is larger than the 100 MB limit.",
                    "details": []
                }
            else:
                result = analyze_file(file_path)

    except (OSError, ValueError) as error:
        result = {
            "status": "Error",
            "message": "The uploaded file could not be analysed.",
            "details": []
        }

    return render_template(
        "index.html",
        malware_analysis=result
    )
