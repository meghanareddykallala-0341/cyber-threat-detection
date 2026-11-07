
from flask import Blueprint, render_template, request, send_from_directory
from werkzeug.utils import secure_filename
from pathlib import Path
import tempfile

from .url_analyser import analyze_url
from .malware_analyser import analyze_file
from .ransomware_analyser import analyze_ransomware_csv

main = Blueprint("main", __name__)

MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB
PROJECT_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_DIR / "reports"

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

    except (OSError, ValueError):
        result = {
            "status": "Error",
            "message": "The uploaded file could not be analysed.",
            "details": []
        }

    return render_template(
        "index.html",
        malware_analysis=result
    )


@main.route("/analyze_ransomware", methods=["POST"])
def analyze_ransomware_route():

    uploaded_file = request.files.get("ransomware_file")

    if not uploaded_file or not uploaded_file.filename:
        result = {
            "status": "Invalid",
            "message": "Please select a SILRAD CSV file.",
            "total_records": 0,
            "goodware_count": 0,
            "ransomware_count": 0,
            "sample_results": [],
            "details": []
        }
        return render_template("index.html", ransomware_analysis=result)

    filename = secure_filename(uploaded_file.filename)

    if not filename or not filename.lower().endswith(".csv"):
        result = {
            "status": "Invalid",
            "message": "Please upload a CSV file.",
            "total_records": 0,
            "goodware_count": 0,
            "ransomware_count": 0,
            "sample_results": [],
            "details": []
        }
        return render_template("index.html", ransomware_analysis=result)

    if (
        request.content_length is not None
        and request.content_length > MAX_UPLOAD_SIZE + 1024 * 1024
    ):
        result = {
            "status": "Invalid",
            "message": "The upload is too large. Maximum file size is 100 MB.",
            "total_records": 0,
            "goodware_count": 0,
            "ransomware_count": 0,
            "sample_results": [],
            "details": []
        }
        return render_template("index.html", ransomware_analysis=result)

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / filename
            uploaded_file.save(file_path)

            if file_path.stat().st_size > MAX_UPLOAD_SIZE:
                result = {
                    "status": "Invalid",
                    "message": "The CSV is larger than the 100 MB limit.",
                    "total_records": 0,
                    "goodware_count": 0,
                    "ransomware_count": 0,
                    "sample_results": [],
                    "details": []
                }
            else:
                result = analyze_ransomware_csv(file_path)

    except (OSError, ValueError):
        result = {
            "status": "Error",
            "message": "The CSV file could not be analysed.",
            "total_records": 0,
            "goodware_count": 0,
            "ransomware_count": 0,
            "sample_results": [],
            "details": []
        }

    return render_template(
        "index.html",
        ransomware_analysis=result
    )
@main.route("/download_ransomware_report/<filename>")
def download_ransomware_report(filename):

    safe_filename = secure_filename(filename)

    if not safe_filename or safe_filename != filename:
        return "Invalid report filename.", 400

    return send_from_directory(
        REPORT_DIR,
        safe_filename,
        as_attachment=True,
        download_name=safe_filename
    )
@main.route("/download_malware_report/<filename>")
def download_malware_report(filename):

    safe_filename = secure_filename(filename)

    if (
        not safe_filename
        or safe_filename != filename
        or not safe_filename.startswith("malware_report_")
        or not safe_filename.endswith(".csv")
    ):
        return "Invalid report filename.", 400

    return send_from_directory(
        REPORT_DIR,
        safe_filename,
        as_attachment=True,
        download_name=safe_filename
    )