# Network Anomaly Detector

This Python project is an ethical hacking tool designed for detecting anomalies in network traffic and checking the reputation of IP addresses using the VirusTotal API.

## Features
- Captures network traffic using Scapy.
- Detects anomalies in the captured traffic using machine learning (`IsolationForest`).
- Checks the reputation of detected IP addresses via the VirusTotal API.
- Generates alerts and logs anomalies.

## Requirements
To use this project, you will need:
- Python 3.8 or higher
- Required Python packages (`scapy`, `pandas`, `scikit-learn`, `matplotlib`, `requests`)

### Install Dependencies
Run the following command to install dependencies:

```bash
git clone https://github.com/your-username/network_anomaly_detector.git
cd network_anomaly_detector
pip install -r requirements.txt
python network_anomaly_detector.py
