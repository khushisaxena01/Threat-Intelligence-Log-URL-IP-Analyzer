import pandas as pd
import numpy as np
import csv
import json
import re
import socket
import requests
import ipaddress
from urllib.parse import urlparse
import tldextract
from multiprocessing import Pool, cpu_count
import threading
import asyncio
import time
from collections import Counter, defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import hashlib
import warnings
warnings.filterwarnings('ignore')

class ThreatIntelligenceAnalyzer:
    """
    Main class for threat intelligence analysis of URLs and IP addresses
    """
    
    def __init__(self, max_workers=None):
        self.max_workers = max_workers or cpu_count()
        self.threat_urls = set()
        self.threat_ips = set()
        self.results = []
        self.statistics = {}
        self.processing_start_time = None
        
    def load_threat_intelligence(self, threat_file_path):
        """
        Load threat intelligence data from various file formats
        """
        print(f"Loading threat intelligence from: {threat_file_path}")
        
        try:
            if threat_file_path.endswith('.csv'):
                df = pd.read_csv(threat_file_path)
            elif threat_file_path.endswith('.txt'):
                with open(threat_file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                df = pd.DataFrame([line.strip().split(',') for line in lines if line.strip()])
            elif threat_file_path.endswith('.json'):
                with open(threat_file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                df = pd.DataFrame(data)
            else:
                raise ValueError("Unsupported file format")
            
            # Extract URLs and IPs from the threat intelligence
            for _, row in df.iterrows():
                for cell in row:
                    if pd.notna(cell):
                        cell_str = str(cell).strip()
                        if self._is_url(cell_str):
                            self.threat_urls.add(cell_str.lower())
                        elif self._is_ip(cell_str):
                            self.threat_ips.add(cell_str)
            
            print(f"Loaded {len(self.threat_urls)} threat URLs and {len(self.threat_ips)} threat IPs")
            
        except Exception as e:
            print(f"Error loading threat intelligence: {e}")
            raise
    
    def _is_url(self, text):
        """Check if text is a valid URL"""
        try:
            result = urlparse(text)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _is_ip(self, text):
        """Check if text is a valid IP address"""
        try:
            ipaddress.ip_address(text)
            return True
        except:
            return False
    
    def _validate_url(self, url):
        """Validate URL accessibility and return classification"""
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Check against threat intelligence
            if url.lower() in self.threat_urls:
                return 'BLOCKED', 'Matches threat intelligence database'
            
            # Extract domain for additional checks
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            # Check for suspicious patterns
            if self._is_suspicious_domain(domain):
                return 'ABNORMAL', 'Suspicious domain characteristics detected'
            
            # Try to access the URL (with timeout)
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    return 'ACCEPTED', f'Accessible (Status: {response.status_code})'
                else:
                    return 'ABNORMAL', f'Unusual status code: {response.status_code}'
            except requests.RequestException:
                return 'REJECTED', 'URL not accessible or timeout'
                
        except Exception as e:
            return 'REJECTED', f'Invalid URL format: {str(e)}'
    
    def _validate_ip(self, ip):
        """Validate IP address and return classification"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check against threat intelligence
            if ip in self.threat_ips:
                return 'BLOCKED', 'Matches threat intelligence database'
            
            # Check for private/reserved IPs
            if ip_obj.is_private:
                return 'ACCEPTED', 'Private IP address'
            elif ip_obj.is_reserved:
                return 'ABNORMAL', 'Reserved IP address'
            elif ip_obj.is_loopback:
                return 'ACCEPTED', 'Loopback IP address'
            
            # Try to connect to the IP
            try:
                socket.setdefaulttimeout(3)
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((str(ip_obj), 80))
                return 'ACCEPTED', 'IP accessible on port 80'
            except:
                try:
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((str(ip_obj), 443))
                    return 'ACCEPTED', 'IP accessible on port 443'
                except:
                    return 'REJECTED', 'IP not accessible on common ports'
                    
        except Exception as e:
            return 'REJECTED', f'Invalid IP format: {str(e)}'
    
    def _is_suspicious_domain(self, domain):
        """Check for suspicious domain characteristics"""
        suspicious_patterns = [
            r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}',  # IP-like domains
            r'[a-z]{20,}',  # Very long random strings
            r'[0-9]{10,}',  # Long numeric sequences
            r'(bit\.ly|tinyurl|t\.co|goo\.gl)',  # URL shorteners
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return True
        return False
    
    def _process_chunk(self, chunk_data):
        """Process a chunk of data for parallel processing"""
        chunk_results = []
        
        for item in chunk_data:
            item = str(item).strip()
            if not item:
                continue
                
            result = {
                'item': item,
                'type': '',
                'classification': '',
                'reason': '',
                'timestamp': datetime.now().isoformat(),
                'threat_match': False
            }
            
            if self._is_url(item):
                result['type'] = 'URL'
                classification, reason = self._validate_url(item)
                result['classification'] = classification
                result['reason'] = reason
                result['threat_match'] = classification == 'BLOCKED'
                
            elif self._is_ip(item):
                result['type'] = 'IP'
                classification, reason = self._validate_ip(item)
                result['classification'] = classification
                result['reason'] = reason
                result['threat_match'] = classification == 'BLOCKED'
                
            else:
                result['type'] = 'UNKNOWN'
                result['classification'] = 'REJECTED'
                result['reason'] = 'Invalid format (not URL or IP)'
            
            chunk_results.append(result)
        
        return chunk_results
    
    def analyze_log_file(self, log_file_path):
        """
        Analyze log file and return threat intelligence results
        """
        print(f"Analyzing log file: {log_file_path}")
        self.processing_start_time = time.time()
        
        # Load log data
        try:
            if log_file_path.endswith('.csv'):
                df = pd.read_csv(log_file_path)
                # Extract all potential URLs and IPs from all columns
                all_items = []
                for col in df.columns:
                    all_items.extend(df[col].dropna().astype(str).tolist())
            elif log_file_path.endswith('.txt'):
                with open(log_file_path, 'r', encoding='utf-8') as f:
                    all_items = [line.strip() for line in f if line.strip()]
            else:
                raise ValueError("Unsupported log file format")
            
            print(f"Loaded {len(all_items)} items for analysis")
            
            # Split data into chunks for parallel processing
            chunk_size = max(1, len(all_items) // self.max_workers)
            chunks = [all_items[i:i + chunk_size] for i in range(0, len(all_items), chunk_size)]
            
            # Process chunks in parallel
            print(f"Processing with {self.max_workers} workers...")
            with Pool(self.max_workers) as pool:
                chunk_results = pool.map(self._process_chunk, chunks)
            
            # Flatten results
            self.results = [item for chunk in chunk_results for item in chunk]
            
            # Calculate statistics
            self._calculate_statistics()
            
            processing_time = time.time() - self.processing_start_time
            print(f"Analysis completed in {processing_time:.2f} seconds")
            
            return self.results
            
        except Exception as e:
            print(f"Error analyzing log file: {e}")
            raise
    
    def _calculate_statistics(self):
        """Calculate comprehensive statistics from results"""
        total_items = len(self.results)
        
        if total_items == 0:
            return
        
        # Classification counts
        classifications = Counter([r['classification'] for r in self.results])
        types = Counter([r['type'] for r in self.results])
        
        # Threat analysis
        threat_matches = sum(1 for r in self.results if r['threat_match'])
        hit_ratio = (threat_matches / total_items) * 100 if total_items > 0 else 0
        security_posture = max(0, 100 - hit_ratio)  # Inverse relationship
        
        self.statistics = {
            'total_items': total_items,
            'classifications': dict(classifications),
            'types': dict(types),
            'threat_matches': threat_matches,
            'hit_ratio': hit_ratio,
            'security_posture': security_posture,
            'processing_time': time.time() - self.processing_start_time if self.processing_start_time else 0
        }
    
    def generate_report(self, output_file=None):
        """Generate comprehensive analysis report"""
        if not self.results:
            print("No results to report")
            return
        
        report = []
        report.append("=" * 50)
        report.append("THREAT INTELLIGENCE ANALYSIS REPORT")
        report.append("=" * 50)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Items Analyzed: {self.statistics['total_items']}")
        report.append(f"Processing Time: {self.statistics['processing_time']:.2f} seconds")
        report.append("")
        
        # Classification Summary
        report.append("CLASSIFICATION SUMMARY:")
        report.append("-" * 25)
        for classification, count in self.statistics['classifications'].items():
            percentage = (count / self.statistics['total_items']) * 100
            report.append(f"{classification}: {count} ({percentage:.1f}%)")
        report.append("")
        
        # Type Summary
        report.append("TYPE SUMMARY:")
        report.append("-" * 15)
        for item_type, count in self.statistics['types'].items():
            percentage = (count / self.statistics['total_items']) * 100
            report.append(f"{item_type}: {count} ({percentage:.1f}%)")
        report.append("")
        
        # Security Analysis
        report.append("SECURITY ANALYSIS:")
        report.append("-" * 20)
        report.append(f"Threat Matches (HITs): {self.statistics['threat_matches']}")
        report.append(f"HIT Ratio: {self.statistics['hit_ratio']:.2f}%")
        report.append(f"Security Posture Score: {self.statistics['security_posture']:.2f}/100")
        report.append("")
        
        # Threat Details
        if self.statistics['threat_matches'] > 0:
            report.append("DETECTED THREATS:")
            report.append("-" * 18)
            for result in self.results:
                if result['threat_match']:
                    report.append(f"• {result['item']} ({result['type']}) - {result['reason']}")
            report.append("")
        
        report_text = "\n".join(report)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"Report saved to: {output_file}")
        else:
            print(report_text)
        
        return report_text
    
    def create_visualizations(self, save_plots=True):
        """Create comprehensive visualizations"""
        if not self.results:
            print("No results to visualize")
            return
        
        # Set up the plotting style
        plt.style.use('seaborn-v0_8')
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Threat Intelligence Analysis Dashboard', fontsize=16, fontweight='bold')
        
        # Classification Distribution (Pie Chart)
        classifications = self.statistics['classifications']
        colors = {'ACCEPTED': 'green', 'REJECTED': 'red', 'BLOCKED': 'darkred', 'ABNORMAL': 'orange'}
        pie_colors = [colors.get(k, 'gray') for k in classifications.keys()]
        
        axes[0, 0].pie(classifications.values(), labels=classifications.keys(), autopct='%1.1f%%',
                       colors=pie_colors, startangle=90)
        axes[0, 0].set_title('Classification Distribution', fontweight='bold')
        
        # Type Distribution (Bar Chart)
        types = self.statistics['types']
        axes[0, 1].bar(types.keys(), types.values(), color=['skyblue', 'lightcoral', 'lightgreen'])
        axes[0, 1].set_title('Item Type Distribution', fontweight='bold')
        axes[0, 1].set_ylabel('Count')
        
        # Security Metrics (Gauge-style)
        security_score = self.statistics['security_posture']
        hit_ratio = self.statistics['hit_ratio']
        
        # Security Posture Gauge
        theta = np.linspace(0, np.pi, 100)
        r = np.ones_like(theta)
        axes[1, 0].plot(theta, r, 'k-', linewidth=2)
        
        # Color coding for security posture
        if security_score >= 80:
            color = 'green'
            status = 'GOOD'
        elif security_score >= 60:
            color = 'orange'
            status = 'MODERATE'
        else:
            color = 'red'
            status = 'POOR'
        
        # Plot security score indicator
        score_angle = np.pi * (1 - security_score / 100)
        axes[1, 0].plot([score_angle, score_angle], [0, 1], color=color, linewidth=4)
        axes[1, 0].text(np.pi/2, 0.5, f'{security_score:.1f}%\n{status}', 
                       ha='center', va='center', fontsize=12, fontweight='bold')
        axes[1, 0].set_title('Security Posture Score', fontweight='bold')
        axes[1, 0].set_ylim(0, 1.2)
        axes[1, 0].axis('off')
        
        # Threat Detection Summary
        threat_data = ['Clean', 'Threats']
        threat_counts = [self.statistics['total_items'] - self.statistics['threat_matches'], 
                        self.statistics['threat_matches']]
        threat_colors = ['lightgreen', 'red']
        
        axes[1, 1].bar(threat_data, threat_counts, color=threat_colors)
        axes[1, 1].set_title('Threat Detection Summary', fontweight='bold')
        axes[1, 1].set_ylabel('Count')
        
        # Add statistics text
        stats_text = f"Total Items: {self.statistics['total_items']}\n"
        stats_text += f"Processing Time: {self.statistics['processing_time']:.2f}s\n"
        stats_text += f"Threat Matches: {self.statistics['threat_matches']}\n"
        stats_text += f"HIT Ratio: {self.statistics['hit_ratio']:.2f}%"
        
        fig.text(0.02, 0.02, stats_text, fontsize=10, 
                bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgray"))
        
        plt.tight_layout()
        
        if save_plots:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_analysis_dashboard_{timestamp}.png"
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"Visualization saved as: {filename}")
        
        plt.show()
    
    def export_results(self, output_file):
        """Export results to CSV file"""
        if not self.results:
            print("No results to export")
            return
        
        df = pd.DataFrame(self.results)
        df.to_csv(output_file, index=False)
        print(f"Results exported to: {output_file}")

def main():
    """
    Main function demonstrating the threat intelligence analyzer
    """
    print("Threat Intelligence Log Analyzer")
    print("=" * 40)
    
    # Initialize analyzer
    analyzer = ThreatIntelligenceAnalyzer()
    
    # Example usage
    try:
        # Load threat intelligence (you would replace with actual file paths)
        # analyzer.load_threat_intelligence("threat_intelligence.csv")
        
        # For demonstration, let's add some sample threat data
        analyzer.threat_urls.update([
            'malicious-site.com',
            'phishing-domain.net',
            'suspicious-url.org'
        ])
        
        analyzer.threat_ips.update([
            '192.168.1.100',
            '10.0.0.50',
            '172.16.0.25'
        ])
        
        # Create sample log data for demonstration
        sample_data = [
            'https://google.com',
            'https://malicious-site.com',
            '8.8.8.8',
            '192.168.1.100',
            'invalid-url',
            'https://github.com',
            '1.1.1.1',
            'suspicious-url.org'
        ]
        
        # Process the sample data
        print("Processing sample data...")
        results = []
        for item in sample_data:
            result = analyzer._process_chunk([item])[0]
            results.append(result)
        
        analyzer.results = results
        analyzer._calculate_statistics()
        
        # Generate report
        print("\nGenerating analysis report...")
        analyzer.generate_report()
        
        # Create visualizations
        print("\nCreating visualizations...")
        analyzer.create_visualizations()
        
        # Export results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        analyzer.export_results(f"threat_analysis_results_{timestamp}.csv")
        
    except Exception as e:
        print(f"Error in main execution: {e}")

if __name__ == "__main__":
    main()
