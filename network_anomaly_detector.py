import os
import time
import requests
import scapy.all as scapy
import pandas as pd
from scapy.layers.inet import IP
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from datetime import datetime
import socket
import struct

def ip_to_int(ip_str):
    packed_ip = socket.inet_aton(ip_str)
    return struct.unpack("!L", packed_ip)[0]

packet_data = []

# Get the VirusTotal API key securely from environment variables
vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')

def capture_traffic(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)
        time = datetime.now()
        packet_data.append([time, src_ip, dst_ip, proto, length])

def detect_anomalies(data, contamination_rate):
    df = pd.DataFrame(data, columns=['Time', 'Source_IP', 'Destination_IP', 'Protocol', 'Length'])

    # Convert IP addresses to integers for IsolationForest model
    df['Source_IP_Int'] = df['Source_IP'].apply(ip_to_int)
    df['Destination_IP_Int'] = df['Destination_IP'].apply(ip_to_int)

    features = df[['Source_IP_Int', 'Destination_IP_Int', 'Protocol', 'Length']]

    if features.shape[0] == 0:
        print("No packets captured, skipping anomaly detection.")
        return

    model = IsolationForest(contamination=contamination_rate)
    model.fit(features)
    df['Anomaly'] = model.predict(features)

    log_anomalies(df)
    visualize_anomalies(df)
    report_anomalies(df)

def visualize_anomalies(df):
    plt.figure(figsize=(12, 8))
    anomalies = df[df['Anomaly'] == -1]  # Anomalous traffic (marked as -1)
    normal = df[df['Anomaly'] == 1]      # Normal traffic (marked as 1)
    
    plt.scatter(normal.index, normal['Length'], c='blue', label='Normal Traffic')
    plt.scatter(anomalies.index, anomalies['Length'], c='red', label='Anomalous Traffic')
    
    plt.title('Network Traffic Anomalies')
    plt.xlabel('Packet Index')
    plt.ylabel('Packet Length')
    plt.legend(loc="upper left")
    
    filename = f"anomalies_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.png"
    plt.savefig(filename)
    plt.show()

def report_anomalies(df):
    anomalies = df[df['Anomaly'] == -1]
    if len(anomalies) == 0:
        print("No anomalies detected.")
    else:
        print(f"Detected {len(anomalies)} anomalies.")
        print("Anomalous packets:")
        print(anomalies[['Time', 'Source_IP', 'Destination_IP', 'Protocol', 'Length']])
        check_ip_reputation(anomalies)

def log_anomalies(df):
    anomalies = df[df['Anomaly'] == -1]
    with open('anomaly_log.txt', 'a') as file:
        if len(anomalies) > 0:
            file.write(f"\nDetected {len(anomalies)} anomalies at {datetime.now()}\n")
            anomalies.to_string(file, columns=['Time', 'Source_IP', 'Destination_IP', 'Protocol', 'Length'])

# Check IP reputation with VirusTotal
def check_ip_reputation(anomalies):
    print("\nChecking IP reputation using VirusTotal...")
    if vt_api_key is None:
        print("VirusTotal API key not found. Please set the 'VIRUSTOTAL_API_KEY' environment variable.")
        return
    
    for index, row in anomalies.iterrows():
        src_ip = row['Source_IP']
        dst_ip = row['Destination_IP']

        # Check Source IP (as a string)
        try:
            response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{src_ip}', headers={"x-apikey": vt_api_key})
            if response.status_code == 200:
                json_response = response.json()
                analysis_stats = json_response["data"]["attributes"]["last_analysis_stats"]
                print(f"Reputation check for {src_ip}: Malicious: {analysis_stats['malicious']}, Harmless: {analysis_stats['harmless']}")
            else:
                print(f"Error checking VirusTotal for {src_ip}: Status code {response.status_code}")
                print(f"Response: {response.text}")
        except Exception as e:
            print(f"Error checking VirusTotal for {src_ip}: {e}")
        time.sleep(15)  

        # Check Destination IP (as a string)
        try:
            response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{dst_ip}', headers={"x-apikey": vt_api_key})
            if response.status_code == 200:
                json_response = response.json()
                analysis_stats = json_response["data"]["attributes"]["last_analysis_stats"]
                print(f"Reputation check for {dst_ip}: Malicious: {analysis_stats['malicious']}, Harmless: {analysis_stats['harmless']}")
            else:
                print(f"Error checking VirusTotal for {dst_ip}: Status code {response.status_code}")
                print(f"Response: {response.text}")
        except Exception as e:
            print(f"Error checking VirusTotal for {dst_ip}: {e}")
        time.sleep(15)  

def sniff_network(packet_count, contamination_rate):
    print(f"Starting real-time network traffic capture...")
    
    scapy.sniff(prn=capture_traffic, count=packet_count)
    
    if len(packet_data) > 0:
        detect_anomalies(packet_data, contamination_rate)
    else:
        print("No packets captured for analysis.")
    
if __name__ == "__main__":
    packet_count = int(input("Enter the number of packets to capture per round: "))
    contamination_rate = float(input("Enter the anomaly detection sensitivity (0-0.5, lower = more sensitive): "))
    if contamination_rate <= 0 or contamination_rate > 0.5:
        print("Invalid contamination rate! Setting to default value of 0.01")
        contamination_rate = 0.01

    sniff_network(packet_count, contamination_rate)
