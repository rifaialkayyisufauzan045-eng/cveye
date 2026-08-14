# CVEye

### CVE Intelligence & Technology Scanner

CVEye adalah **vulnerability assessment tool berbasis Python** yang digunakan untuk mengidentifikasi service, teknologi web, versi software, dan menghubungkannya dengan informasi CVE yang relevan.

CVEye menggabungkan:

* Network discovery
* TCP port scanning
* Service fingerprinting
* Web technology detection
* Software version detection
* Security header analysis
* TLS information
* CVE correlation
* CVE web intelligence
* Risk assessment
* JSON/HTML reporting

> **CVEye tidak melakukan exploitation.** Tool ini dirancang untuk assessment dan reconnaissance terhadap sistem yang dimiliki atau telah mendapatkan izin pengujian.

---

## ✨ Features

### Network Scanning

CVEye dapat mendeteksi:

```text
IP Address
Hostname
Open TCP Ports
Services
Service Banners
Service Versions
```

Contoh:

```text
22/tcp   SSH
80/tcp   HTTP
443/tcp  HTTPS
3306/tcp MySQL
```

### Web Technology Detection

CVEye dapat melakukan fingerprinting terhadap teknologi yang digunakan website, misalnya:

```text
Nginx
Apache
LiteSpeed
PHP
WordPress
Drupal
Joomla
```

Jika informasi versi tersedia, CVEye juga mencoba mengidentifikasi versinya.

Contoh:

```text
Nginx
Version    : 1.24.0
Confidence : HIGH

PHP
Version    : 7.4.33
Confidence : HIGH

WordPress
Version    : 6.8.7
Confidence : HIGH
```

### CVE Intelligence

Setelah software dan versinya ditemukan, CVEye dapat mencari informasi CVE yang relevan.

Flow:

```text
Target
   ↓
Network/Web Scan
   ↓
Technology Detection
   ↓
Version Detection
   ↓
CVE Intelligence
   ↓
Version Matching
   ↓
Risk Assessment
   ↓
Report
```

CVEye menggunakan informasi dari sumber vulnerability publik dan dapat menggunakan web search sebagai lapisan intelligence tambahan.

Hasil pencarian tidak langsung dianggap sebagai vulnerability. CVEye mencoba mencocokkan:

```text
Vendor
+
Product
+
Version
+
Affected Version Range
```

---

# 🖥️ Installation

## 1. Clone Repository

Di perangkat lain, pastikan Git dan Python sudah tersedia.

Clone repository:

```bash
git clone https://github.com/RifaiAl31/cveye.git
```

Masuk ke directory:

```bash
cd CVEye
```

---

## 2. Buat Virtual Environment

Disarankan menggunakan virtual environment agar dependency CVEye tidak mengganggu Python sistem.

```bash
python3 -m venv .venv
```

Aktifkan:

### Linux/macOS

```bash
source .venv/bin/activate
```

### Windows

```powershell
.venv\Scripts\activate
```

---

## 3. Install CVEye

Install project dalam editable mode:

```bash
python -m pip install -e .
```

**Penting:** gunakan `.` setelah `-e`.

Benar:

```bash
pip install -e .
```

Salah:

```bash
pip install -e
```

---

## 4. Install Dependencies

Jika project menggunakan `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## 5. Chromium

Jika CVEye menggunakan Chromium untuk CVE web intelligence, install Playwright:

```bash
pip install playwright
```

Kemudian install Chromium:

```bash
playwright install chromium
```

Pada beberapa distro Linux, jika dependency sistem belum tersedia:

```bash
playwright install-deps chromium
```

---

# 🚀 Usage

Setelah installation selesai, cek:

```bash
cveye --help
```

Cek versi:

```bash
cveye version
```

---

## Basic Scan

```bash
cveye scan example.com
```

CVEye akan melakukan proses:

```text
Resolving target
       ↓
Network discovery
       ↓
Port scanning
       ↓
Service fingerprinting
       ↓
Web fingerprinting
       ↓
Version detection
       ↓
CVE intelligence
       ↓
Risk analysis
```

---

## Scan IP

```bash
cveye scan 192.168.1.10
```

---

## Scan Website

```bash
cveye scan https://example.com
```

---

## Custom Ports

```bash
cveye scan 192.168.1.10 --ports 22,80,443,8080
```

---

## Web Scan

```bash
cveye scan example.com --web
```

---

## CVE Analysis

```bash
cveye scan example.com --cve
```

CVEye akan menggunakan software dan versi yang ditemukan untuk melakukan CVE correlation.

---

# 📊 Example Output

```text
CVEye
CVE Intelligence & Technology Scanner

Target
  Hostname : example.com
  IP       : 192.168.1.10

OPEN PORTS

  22/tcp
    Service : SSH

  80/tcp
    Service : HTTP

  443/tcp
    Service : HTTPS


WEB TECHNOLOGY

  Nginx
    Version    : 1.24.0
    Confidence : HIGH

  PHP
    Version    : 8.2.12
    Confidence : HIGH

  WordPress
    Version    : 6.8.7
    Confidence : HIGH


CVE INTELLIGENCE

  PHP 8.2.12
    Searching CVE...
    Verifying results...

  WordPress 6.8.7
    Searching CVE...
    Verifying results...


CVE FINDINGS

  HIGH
    CVE-XXXX-XXXX
    Product : PHP
    Status  : AFFECTED
    CVSS    : 8.1

  MEDIUM
    CVE-XXXX-XXXX
    Product : WordPress
    Status  : POTENTIALLY AFFECTED


RISK SUMMARY

  CRITICAL : 0
  HIGH     : 1
  MEDIUM   : 1
  LOW      : 0
```

---

# 📁 Project Structure

```text
CVEye/
├── cveye/
│   ├── network/
│   ├── web/
│   ├── fingerprint/
│   ├── cve/
│   ├── risk/
│   ├── reporting/
│   └── utils/
│
├── tests/
├── README.md
├── LICENSE
├── pyproject.toml
└── requirements.txt
```

---

# 🔍 How CVEye Works

CVEye menggunakan beberapa tahap.

### 1. Discovery

Menentukan target dan informasi jaringan yang tersedia.

### 2. Port Scanning

Mendeteksi port TCP yang terbuka.

### 3. Service Detection

Mengidentifikasi service berdasarkan response/banner.

### 4. Technology Fingerprinting

Mengidentifikasi teknologi website.

Contoh:

```text
LiteSpeed
PHP
WordPress
```

### 5. Version Detection

Mencoba mendapatkan versi software dari evidence yang tersedia.

### 6. CVE Intelligence

Software dan versi yang ditemukan digunakan untuk mencari vulnerability yang relevan.

### 7. Version Matching

CVEye membandingkan versi target dengan affected version range.

Hasil dapat berupa:

```text
AFFECTED
POTENTIALLY AFFECTED
NOT AFFECTED
UNKNOWN
```

### 8. Reporting

Hasil akhirnya ditampilkan melalui CLI dan dapat disimpan dalam format laporan.

---

# ⚠️ Important: Unknown Version

CVEye tidak boleh menganggap semua CVE sebuah software sebagai vulnerability.

Misalnya:

```text
MySQL
Version : UNKNOWN
```

CVEye tidak akan menganggap seluruh CVE MySQL sebagai vulnerability.

Hasilnya:

```text
CVE Analysis:
SKIPPED

Reason:
Exact version unavailable
```

Hal ini dilakukan untuk mengurangi false positive.

---

# 📄 Output Formats

CVEye dapat menghasilkan:

```text
Terminal
JSON
HTML
```

Contoh:

```bash
cveye scan example.com --json report.json
```

atau:

```bash
cveye scan example.com --html report.html
```

---

# 🧪 Testing

Jalankan:

```bash
pytest
```

Untuk memastikan komponen utama berjalan dengan baik.

---

# 🛠️ Development

Clone repository:

```bash
git clone https://github.com/USERNAME/CVEye.git
cd CVEye
```

Buat environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install:

```bash
pip install -e .
pip install -r requirements.txt
```

Jika menggunakan Chromium:

```bash
playwright install chromium
```

Jalankan:

```bash
cveye --help
```

---

# 🔐 Responsible Use

CVEye dibuat untuk:

* Security learning
* Vulnerability assessment
* Security auditing
* Lab environment
* CTF yang mengizinkan scanning
* Sistem milik sendiri
* Authorized penetration testing

**Jangan melakukan scanning terhadap sistem yang tidak kamu miliki atau tidak memiliki izin untuk mengujinya.**

CVEye tidak menyediakan fitur exploitation otomatis.

---

# 🎯 Project Goals

Tujuan pengembangan CVEye adalah membuat vulnerability assessment tool yang:

* Akurat
* Modular
* Mudah digunakan
* Meminimalkan false positive
* Menggabungkan network dan web fingerprinting
* Menghubungkan software version dengan CVE
* Menyediakan evidence dan confidence
* Mudah dikembangkan dengan detector baru

---

# 📌 Roadmap

* [x] Network discovery
* [x] Port scanning
* [x] Service detection
* [x] Web fingerprinting
* [x] Version detection
* [x] Security headers
* [x] TLS information
* [x] CVE correlation
* [ ] Improved CVE web intelligence
* [ ] More technology detectors
* [ ] Improved version matching
* [ ] CVE caching
* [ ] Advanced HTML dashboard
* [ ] Plugin-based fingerprint engine
* [ ] Improved risk scoring

---

## License

See `LICENSE` for license information.
