# Testing Plan - Phase A Verification

## 🎯 Objectives

Verify all implemented modules work correctly against real vulnerable targets:
1. SQL Injection Detection
2. XSS Detection  
3. Subdomain Enumeration

---

## 🧪 Test Targets

### 1. SQL Injection Testing

**Target Options:**
- **testphp.vulnweb.com** - Public vulnerable site
- **demo.testfire.net** - Altoro Mutual (SQLi vulnerabilities)
- **httpbin.org** - Parameter testing

**Test URLs:**
```
http://testphp.vulnweb.com/artists.php?artist=1
http://testphp.vulnweb.com/listproducts.php?cat=1
```

### 2. XSS Testing

**Target Options:**
- **xss-game.appspot.com** - Google's XSS challenge
- **testphp.vulnweb.com** - Has XSS vulnerabilities
- **demo.testfire.net** - Has reflected XSS

**Test URLs:**
```
http://testphp.vulnweb.com/search.php?test=query
http://testphp.vulnweb.com/comment.php?aid=1
```

### 3. Subdomain Enumeration

**Target Options:**
- **hackerone.com** - Many known subdomains
- **example.com** - Simple test
- **github.com** - Large subdomain infrastructure

---

## 📋 Test Cases

### SQL Injection Tests

#### Test 1: Time-Based Blind SQL Injection
```powershell
.\apjson.exe --enable-injection --verbose `
  http://testphp.vulnweb.com/artists.php?artist=1
```

**Expected Results:**
- ✅ Detects time-based SQLi
- ✅ Identifies database type (MySQL)
- ✅ Reports in HTML with evidence
- ✅ Severity: High
- ✅ Confidence: 0.85+

#### Test 2: Error-Based SQL Injection
```powershell
.\apjson.exe --enable-injection --verbose `
  http://testphp.vulnweb.com/listproducts.php?cat=1
```

**Expected Results:**
- ✅ Detects error-based SQLi
- ✅ Extracts database error messages
- ✅ Confidence: 0.95
- ✅ Provides remediation advice

---

### XSS Tests

#### Test 3: Reflected XSS
```powershell
.\apjson.exe --enable-injection --verbose `
  http://testphp.vulnweb.com/search.php?test=query
```

**Expected Results:**
- ✅ Detects reflected XSS
- ✅ Identifies injection context
- ✅ Shows evidence in report
- ✅ Severity: High

---

### Subdomain Tests

#### Test 4: Subdomain Enumeration
```powershell
.\apjson.exe --enable-subdomains --verbose `
  https://example.com
```

**Expected Results:**
- ✅ Discovers subdomains via DNS bruteforce
- ✅ Resolves IP addresses
- ✅ Saves results to file
- ✅ Statistics in report

---

## ✅ Success Criteria

### For Each Module:

**SQL Injection:**
- [ ] Detects at least 1 vulnerability
- [ ] Correct technique identification
- [ ] Accurate database fingerprinting
- [ ] Evidence properly extracted
- [ ] Report includes remediation

**XSS:**
- [ ] Detects reflected payloads
- [ ] Context correctly identified  
- [ ] Evidence extracted from response
- [ ] No false positives on safe sites

**Subdomain Enumeration:**
- [ ] Discovers known subdomains
- [ ] IP resolution works
- [ ] Results saved correctly
- [ ] Statistics accurate

---

## 📊 Test Execution Log

### Test 1: SQLi on testphp.vulnweb.com
**Status:** PENDING
**Command:** `.\apjson.exe --enable-injection http://testphp.vulnweb.com/artists.php?artist=1`
**Results:** 
- Vulnerabilities Found: 
- Database Detected:
- Technique Used:
- Duration:

### Test 2: XSS on testphp.vulnweb.com
**Status:** PENDING
**Command:** `.\apjson.exe --enable-injection http://testphp.vulnweb.com/search.php?test=query`
**Results:**
- XSS Found:
- Context:
- Payload:
- Duration:

### Test 3: Subdomain Enum on example.com
**Status:** PENDING
**Command:** `.\apjson.exe --enable-subdomains https://example.com`
**Results:**
- Subdomains Found:
- Resolved:
- Takeovers:
- Duration:

---

## 🔧 Troubleshooting

**If SQLi not detected:**
- Check if target is actually vulnerable
- Verify timeout is sufficient (default: 600s)
- Check baseline response time
- Review payload list

**If XSS not detected:**
- Verify payload reflection
- Check encoding issues
- Review context detection logic
- Test with simple payloads first

**If Subdomains empty:**
- Check DNS resolution
- Verify Subfinder installation
- Try bruteforce-only mode
- Check network connectivity

---

## 📝 Notes

- All tests should be run on **publicly vulnerable sites**
- **Never test** on production systems without permission
- Document all findings for validation
- Compare with manual testing results
