import os, sqlite3, ipaddress, socket, subprocess, platform, requests
from flask import Flask, request, render_template, redirect, url_for, Response
from functools import wraps
import threading, time, csv, json

DB_FILE = "portal.db"
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", 7))

app = Flask(__name__)

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_original TEXT, ip_masked TEXT, 
            user_agent TEXT, language TEXT, 
            hostname TEXT, local_ip TEXT, dns_servers TEXT,
            forwarded_for TEXT, referer TEXT,
            public_ip TEXT, network_devices TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')

def get_network_info():
    """Sunucu ağ bilgilerini topla"""
    info = {}
    try:
        # Local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info['local_ip'] = s.getsockname()[0]
        s.close()
        
        # Hostname
        info['hostname'] = socket.gethostname()
        
        # DNS Servers (Windows için)
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['nslookup', 'google.com'], capture_output=True, text=True, timeout=5)
                dns_info = result.stdout
                info['dns_servers'] = dns_info
            else:
                info['dns_servers'] = "Linux/Mac DNS bilgisi"
        except:
            info['dns_servers'] = "DNS bilgisi alınamadı"
            
    except Exception as e:
        info = {'local_ip': 'Bilinmiyor', 'hostname': 'Bilinmiyor', 'dns_servers': f'Hata: {str(e)}'}
    
    return info

def scan_network():
    """Ağdaki diğer cihazları tara (eğitim amaçlı)"""
    devices = []
    try:
        # Local network range'i bul
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # IP range'i oluştur (örn: 192.168.1.0/24)
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        
        # Sadece birkaç IP'yi tara (hız için)
        test_ips = [str(ip) for ip in list(network.hosts())[:10]]
        
        for ip in test_ips:
            try:
                # Ping test (Windows)
                if platform.system() == "Windows":
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                          capture_output=True, text=True, timeout=2)
                    if "Reply from" in result.stdout:
                        devices.append({
                            'ip': ip,
                            'status': 'active',
                            'response_time': 'fast'
                        })
                else:
                    # Linux/Mac
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                          capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        devices.append({
                            'ip': ip,
                            'status': 'active',
                            'response_time': 'fast'
                        })
            except:
                continue
                
    except Exception as e:
        devices.append({'error': str(e)})
    
    return devices

def get_public_ip():
    """Public IP adresini al"""
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text.strip()
    except:
        return "Bilinmiyor"

def mask_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return ".".join(ip.split(".")[:3]) + ".✱"
        else:
            return str(addr).rsplit(":", 1)[0] + ":✱"
    except:
        return "unknown"

def check_auth(u, p): return u == ADMIN_USER and p == ADMIN_PASSWORD
def authenticate(): return Response("Auth required", 401, {"WWW-Authenticate": "Basic realm='Login'"})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def index():
    user_ip = request.remote_addr
    return render_template("index.html", user_ip=user_ip)

@app.route("/accept", methods=["POST"])
def accept():
    # Orijinal IP (eğitim amaçlı - gerçek projede kullanılmamalı)
    ip_original = request.remote_addr
    ip_masked = mask_ip(ip_original)
    
    # HTTP Header bilgileri
    ua = request.headers.get("User-Agent", "-")
    lang = request.headers.get("Accept-Language", "-")
    forwarded_for = request.headers.get("X-Forwarded-For", "-")
    referer = request.headers.get("Referer", "-")
    
    # Sunucu ağ bilgileri
    network_info = get_network_info()
    
    # Public IP bilgisi (arka planda)
    try:
        public_ip = get_public_ip()
    except:
        public_ip = "Bilinmiyor"
    
    # Ağ tarama (eğitim amaçlı)
    try:
        network_devices = scan_network()
        devices_json = json.dumps(network_devices)
    except:
        devices_json = "[]"
    
    # Veritabanına kaydet
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""INSERT INTO events(ip_original, ip_masked, user_agent, language, 
                        hostname, local_ip, dns_servers, forwarded_for, referer, 
                        public_ip, network_devices) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                    (ip_original, ip_masked, ua, lang, 
                     network_info.get('hostname', ''), 
                     network_info.get('local_ip', ''),
                     network_info.get('dns_servers', ''),
                     forwarded_for, referer, public_ip, devices_json))
    
    return render_template("accepted.html", ip=ip_masked)

@app.route("/admin")
@requires_auth
def admin():
    with sqlite3.connect(DB_FILE) as conn:
        # Tüm kayıtları getir (ID dahil)
        rows = conn.execute("""SELECT id, ip_original, ip_masked, user_agent, language, 
                              hostname, local_ip, dns_servers, forwarded_for, referer, 
                              public_ip, network_devices, timestamp 
                              FROM events ORDER BY timestamp DESC""").fetchall()
        
        # İstatistikleri hesapla
        total_connections = len(rows)
        unique_ips = len(set(row[1] for row in rows))  # Orijinal IP'ler (row[1])
        
        # Bugünkü bağlantıları hesapla
        today_connections = conn.execute(
            "SELECT COUNT(*) FROM events WHERE DATE(timestamp) = DATE('now')"
        ).fetchone()[0]
        
    return render_template("admin.html", 
                         rows=rows, 
                         total_connections=total_connections,
                         unique_ips=unique_ips,
                         today_connections=today_connections)

@app.route("/details/<int:event_id>")
@requires_auth
def event_details(event_id):
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute("""SELECT * FROM events WHERE id = ?""", (event_id,)).fetchone()
    
    if not row:
        return "Kayıt bulunamadı", 404
    
    # Network devices JSON'ını parse et
    try:
        network_devices = json.loads(row[11]) if row[11] else []
    except:
        network_devices = []
    
    return render_template("details.html", event=row, network_devices=network_devices)

@app.route("/export")
@requires_auth
def export_csv():
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute("""SELECT ip_original, ip_masked, user_agent, language, 
                              hostname, local_ip, dns_servers, forwarded_for, referer, timestamp 
                              FROM events ORDER BY timestamp DESC""").fetchall()
    
    def generate():
        yield "Orijinal_IP,Maskelenmiş_IP,Cihaz_Bilgisi,Dil,Hostname,Local_IP,DNS_Servers,Forwarded_For,Referer,Zaman\n"
        for row in rows:
            yield f'"{row[0]}","{row[1]}","{row[2]}","{row[3]}","{row[4]}","{row[5]}","{row[6]}","{row[7]}","{row[8]}","{row[9]}"\n'
    
    return Response(generate(), 
                   mimetype="text/csv",
                   headers={"Content-Disposition": "attachment; filename=captive_portal_detailed_data.csv"})

def retention_worker():
    while True:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("DELETE FROM events WHERE timestamp < datetime('now', ?)", (f'-{RETENTION_DAYS} days',))
        time.sleep(3600)

def print_ascii_banner():
    """ASCII banner yazdır"""
    banner = """
    ██████╗ ███████╗███╗   ██╗██╗███████╗    ███████╗██╗  ██╗███████╗
    ██╔══██╗██╔════╝████╗  ██║██║╚══███╔╝    ██╔════╝╚██╗██╔╝██╔════╝
    ██║  ██║█████╗  ██╔██╗ ██║██║  ███╔╝     █████╗   ╚███╔╝ █████╗  
    ██║  ██║██╔══╝  ██║╚██╗██║██║ ███╔╝      ██╔══╝   ██╔██╗ ██╔══╝  
    ██████╔╝███████╗██║ ╚████║██║███████╗ ██╗███████╗██╔╝ ██╗███████╗
    ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝ ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝
    
    ╔══════════════════════════════════════════════════════════════════╗
    ║                  🛡️  CAPTIVE PORTAL ADVANCED  🛡️                ║
    ║                     Eğitim/Test Amaçlı Sistem                    ║
    ║                                                                  ║
    ║  🔍 IP Toplama        📡 Ağ Tarama       🔐 Admin Paneli        ║
    ║  🌐 DNS Analizi       📊 İstatistikler   ⚠️  Güvenlik Testi      ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    [INFO] Sunucu başlatılıyor...
    [INFO] Eğitim amaçlı ağ analiz sistemi aktif
    [WARNING] Bu yazılım sadece eğitim ve test amaçlıdır!
    """
    print(banner)

if __name__ == "__main__":
    print_ascii_banner()
    init_db()
    threading.Thread(target=retention_worker, daemon=True).start()
    print(f"[SUCCESS] Captive Portal başlatıldı!")
    print(f"[INFO] Ana Sayfa: http://localhost:8000")
    print(f"[INFO] Admin Panel: http://localhost:8000/admin")
    print(f"[INFO] Kullanıcı: admin | Şifre: changeme")
    print("=" * 70)
    app.run(host="0.0.0.0", port=8000)
