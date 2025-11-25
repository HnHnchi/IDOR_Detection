# 🔐 IDOR Scanner

A lightweight, authorized-testing tool for detecting **Insecure Direct Object Reference (IDOR)** vulnerabilities by fuzzing object IDs, comparing responses, and identifying abnormal access patterns.

---

## 🚀 Features
- Baseline request comparison  
- Numeric & range-based ID enumeration  
- Wordlist support  
- Base64 variant testing  
- Body similarity checking (SequenceMatcher)  
- GET & POST support  
- Cookie or Authorization header authentication  

---

## 📦 Installation
```bash
git clone https://github.com/username/idor-scanner.git
cd idor-scanner
pip install -r requirements.txt
```
▶️ Usage
Basic Example
```
python idor_scanner.py \
  --url "https://example.com/profile?user_id=123" \
  --cookie "session=XXXX" \
  --param user_id \
  --candidates 122,124,200-210
```

With POST
```
python idor_scanner.py \
  --url "https://example.com/update" \
  --method POST \
  --data "uid={user_id}&save=1" \
  --param user_id \
  --candidates 100-200
```

📁 Project Structure
```
idor-scanner/
│── idor_scanner.py
│── README.md
│── requirements.txt
```

📌 Notes
```

For authorized testing only.

Similarity ratio ≥ threshold indicates a possible IDOR — always manually verify.

Extend functionality by modifying candidate lists or response heuristics.
