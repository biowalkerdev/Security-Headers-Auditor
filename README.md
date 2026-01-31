# Security Headers Auditor
<img src=https://camo.githubusercontent.com/ac0e6350bd1a747fd6c3ffa64781612d3997df0c837a082a30d7af82a79ee225/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f76657273696f6e2d312e302d626c7565> <img src=https://camo.githubusercontent.com/7013272bd27ece47364536a221edb554cd69683b68a46fc0ee96881174c4214c/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f6c6963656e73652d4d49542d626c75652e737667>
What is this tool about?  
This tool scans websites for vulnerabilities such as CSP, HSTS, etc.  
This tool is very useful for pentesters
## ⭐Features
- Recommendations how to upgrade security of your website
- A-F Ratings
- 9 Security Headers:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - X-XSS-Protection
  - Cache-Control
  - Server Information
- Color-coded terminal output

## Requirments
- Python 3
- Requests
- Colorama

## 🚀How to install
Cloning repository  
```git clone https://github.com/biowalkerdev/Security-Headers-Auditor.git```

```cd Security-Headers-Auditor```

# 📦Installing Dependencies:
On Linux: ```bash install_req.sh```

On Windows: Open file install_req.bat

## Usage (Linux)
Basic scan:
```python3 main.py example.com```

Timeout Scan:
```python3 main.py --timeout 30 https://example.com```

Custom User Agent:
```python3 main.py --user-agent "Mozilla/5.0" https://example.com```

## Usage (Windows)
Basic scan:
```python main.py example.com```

Timeout scan:
```python main.py --timeout 30 https://example.com```

Custom User Agent:
```python main.py --user-agent "Mozilla/5.0" https://example.com```

## 🔧Troubleshooting
While installing dependencies on linux there is can be error:  
This environment is externally managed  
To fix this, create a virtual environment. Here's how:  
```python3 -m venv venv```  
```source venv/bin/activate```  
Now you can install dependencies  
```bash install.req```

## Credits
Made by: biowalkerdev  
Translated to english by: DeepSeek (AI)
