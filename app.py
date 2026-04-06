from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from network_scanner import NetworkScanner
from config_analyzer import ConfigAnalyzer
import json
import time

app = Flask(__name__)
CORS(app)

# Initialize scanners
network_scanner = NetworkScanner()
config_analyzer = ConfigAnalyzer()

@app.route('/')
def home():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    """Return empty response for favicon requests"""
    return '', 204

@app.route('/scan-network', methods=['POST'])
def scan_network():
    """Scan a network range for open ports"""
    try:
        data = request.json
        network = data.get('network', '192.168.1.0/24')
        
        if not network:
            return jsonify({'error': 'No network provided'}), 400
        
        print(f"[INFO] Scanning network: {network}")
        
        # Scan the network
        results = network_scanner.scan_network(network)
        
        return jsonify({
            'success': True,
            'network': network,
            'results': results,
            'total_devices': len(results)
        })
    
    except Exception as e:
        print(f"[ERROR] Network scan failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan-single-ip', methods=['POST'])
def scan_single_ip():
    """Scan a single IP address"""
    try:
        data = request.json
        ip = data.get('ip', '')
        
        if not ip:
            return jsonify({'error': 'No IP address provided'}), 400
        
        print(f"[INFO] Scanning IP: {ip}")
        
        # Scan single IP
        results = network_scanner.scan_single_ip(ip)
        
        return jsonify({
            'success': True,
            'ip': ip,
            'results': results,
            'total_ports': len(results.get(ip, []))
        })
    
    except Exception as e:
        print(f"[ERROR] Single IP scan failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/analyze-config', methods=['POST'])
def analyze_config():
    """Analyze Cisco config for security issues"""
    try:
        data = request.json
        config_text = data.get('config', '')
        
        if not config_text:
            return jsonify({'error': 'No config provided'}), 400
        
        print(f"[INFO] Analyzing config (length: {len(config_text)} chars)")
        
        # Analyze the config
        results = config_analyzer.analyze_config(config_text)
        
        return jsonify({
            'success': True,
            'results': results
        })
    
    except Exception as e:
        print(f"[ERROR] Config analysis failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'services': {
            'network_scanner': 'ready',
            'config_analyzer': 'ready'
        }
    })

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 AI Unified Network Security Platform")
    print("=" * 50)
    print(f"📍 Network Scanner: Ready")
    print(f"📍 Config Analyzer: Ready (Gemini 2.5 Flash)")
    print(f"🌐 Running on: http://localhost:5001")
    print("=" * 50)
    app.run(debug=True, port=5001)