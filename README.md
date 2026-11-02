# CyberShield 🛡️
## AI-Based Phishing, Malware & Ransomware Detection Framework

**College Major Project — Python, Flask and Machine Learning**

CyberShield is a cybersecurity prototype designed to analyse potentially suspicious URLs and inspect Windows executable files using basic static-analysis techniques. The project aims to develop further towards machine-learning-based threat detection and, eventually, ransomware detection.

> **Disclaimer:** CyberShield is a work in progress. Its current checks are preliminary and do not guarantee that a URL or file is safe or malicious. Detection performance has not yet been independently validated.

---

## 📁 Project Structure

```text
cyber-threat-detection/
├── app/
│   ├── __init__.py
│   ├── routes.py
│   ├── url_analyser.py
│   ├── malware_analyser.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/
│       │   └── style.css
│       ├── js/
│       │   └── main.js
│       └── img/
├── datasets/
│   ├── urls.csv
│   └── phishing_features.csv
├── models/
│   └── phishing_model.joblib
├── train_phishing_model.py
├── check_phishing_model.py
├── test_phishing_predictions.py
├── run.py
├── requirements.txt
└── README.md
```

*Some files may be added or changed as development continues.*

---

## 🚀 Setup on macOS

### 1. Check Python

```bash
python3 --version
```

Python 3.9 or newer is recommended, subject to the compatibility of the installed dependencies.

### 2. Open the project directory

```bash
cd ~/Desktop/cyber-threat-detection
```

### 3. Create a virtual environment

If you have not already created one:

```bash
python3 -m venv venv
```

### 4. Activate the environment

```bash
source venv/bin/activate
```

### 5. Install dependencies

```bash
python -m pip install -r requirements.txt
```

The project uses Flask for the web application, pandas and scikit-learn for data processing and machine learning, joblib for loading the saved model, and pefile for inspecting Windows executable metadata.

If a required package is missing, install it in the active virtual environment.

### 6. Start CyberShield

Use the project's configured startup command:

```bash
python run.py
```

If `run.py` uses a different port or startup configuration, follow the settings in that file. The current development configuration used during testing is port **5051**.

### 7. Open the website

Visit:

http://127.0.0.1:5051

If your `run.py` uses another port, replace `5051` with the port shown in your terminal.

### Stop the server

Press **Control + C** in Terminal.

---

## 🔍 Current Features

### 1. Phishing URL Analysis

- Accepts a URL entered by the user.
- Extracts URL characteristics such as length, digits, subdirectories, and suspicious words.
- Uses a saved scikit-learn model to produce a prediction.
- Displays preliminary risk information and explanatory warnings.

**Limitation:** The current training dataset is highly imbalanced, so the model needs stronger evaluation before its reliability can be established.

### 2. Static Malware File Analysis

- Accepts a file upload through the web interface.
- Checks whether a file can be parsed as a Windows Portable Executable (PE).
- Calculates the file's SHA-256 hash and byte entropy.
- Inspects basic executable metadata and reports selected structural warnings.
- Does not intentionally execute the uploaded file.

**Limitation:** This module uses basic static-analysis heuristics, not a trained malware classifier. High entropy or missing metadata alone does not prove that a file is malicious.

### 3. Ransomware Detection — Planned

Potential future work includes research into labelled ransomware datasets, safe static features, and machine-learning approaches to distinguish ransomware-related indicators from benign software.

This feature is **not yet implemented**.

---

## 🗺️ Development Roadmap

| Step | Feature | Status |
|---|---|---|
| 1 | Flask application and homepage | Done |
| 2 | Phishing URL analysis | Implemented; further validation needed |
| 3 | File upload and basic PE analysis | Implemented; integration testing needed |
| 4 | Improved ML training and evaluation | In progress |
| 5 | Ransomware detection module | Planned |
| 6 | Dashboard and results visualisation | Planned |
| 7 | Deep-learning or multimodal experiments | Future research |

---

## 🧰 Technology Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **Machine learning:** scikit-learn
- **Data processing:** pandas
- **Model persistence:** joblib
- **Executable metadata analysis:** pefile
- **Future research:** TensorFlow or PyTorch, depending on the selected approach and available dataset

---

## 🧪 Testing and Evaluation

The project should be evaluated with labelled datasets that contain both benign and malicious examples.

Evaluation should include:
- Confusion matrix
- Precision and recall for each class
- F1-score
- False-positive and false-negative rates
- Tests on data that was not used for training

Accuracy alone can be misleading when the dataset is highly imbalanced. Performance figures should only be reported after appropriate testing.

---

## ⚠️ Security Disclaimer

CyberShield is an educational prototype, not a replacement for professional antivirus or endpoint security software.

Do not execute suspicious files to test the application. Only analyse files you are authorised to inspect. Uploaded files should be handled securely, and no detection result should be treated as a guarantee of safety.

---

*Built as a college major project to explore practical cybersecurity and machine-learning techniques.*