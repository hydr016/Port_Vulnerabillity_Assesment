# Port Scanning and Vulnerability Assessment

> **Only scan systems that you are explicitly authorized to test.**

A Python + Nmap + Flask application that scans one authorized machine, lists its open ports and services, performs basic **non-destructive** security checks, and writes two JSON reports shown on a web dashboard. It never exploits, brute-forces, evades or disrupts anything.

## 1. What this project does
Authorized target -> validate -> Nmap scan -> ports/services/versions -> basic checks -> evidence -> severity -> recommendation -> JSON reports -> dashboard.

## 2. Why port scanning is useful
Every open port is a door into a system. Knowing which doors are open (and what is behind them) lets administrators close what is not needed.

## 3. What vulnerability assessment means
Finding and reporting *possible* weaknesses with evidence and advice. It does not prove a weakness can be exploited, and it does not exploit it.

## 4. How Nmap is used
`nmap -sT -sV --version-intensity 5 -T3 --top-ports 1000 -oX - [--script ...] <address>`
* `-sT` TCP connect scan (no admin rights needed), `-sV` service/version detection, `-oX -` XML output read by our parser.
* No `-A`, no `-O`, no evasion options. Timing is the normal `-T3`.

**NSE scripts used (safe, read-only checks; listed in `config.json`):**
| Script | Why |
|---|---|
| ftp-anon | Checks whether FTP accepts anonymous login (configuration check) |
| http-methods | Lists enabled HTTP methods and flags risky ones (PUT, DELETE, TRACE) |
| ssl-enum-ciphers | Lists TLS versions/ciphers to spot weak TLS settings |
| sslv2 | Checks whether the obsolete SSLv2 protocol is offered |
| smb-security-mode | Reads SMB signing/guest settings |

No exploit, brute-force, DoS or "intrusive" scripts are used. If NSE fails, the app retries without scripts.

## 5. How the application works
```
 Browser (dashboard.html + script.js)
        |  POST /api/scan   GET /api/status   GET /api/results
        v
 app.py (Flask) --> scanner/validator.py        checks the target
                |-> scanner/nmap_scanner.py     runs Nmap (no shell)
                |-> scanner/parser.py           XML -> PortRecord objects
                |-> scanner/vulnerability_engine.py   rules -> Finding objects
                |-> models/schemas.py           builds the JSON structure
                v
        output/port_scan.json   output/vulnerabilities.json
```
The vulnerability engine **never touches the target**; it only reads what Nmap collected. An open port alone is not a finding. A finding needs evidence from the scan:
1. **Sensitive/insecure service** (e.g. Telnet, FTP, exposed database) - based on the service name.
2. **Outdated version** - version older than a baseline table (e.g. OpenSSH < 8.0). Always "Low" confidence, because Linux vendors back-port fixes.
3. **Known indicator** - e.g. vsftpd 2.3.4 (publicly documented backdoor, "requires further verification"; not tested).
4. **NSE results** - anonymous FTP, risky HTTP methods, weak TLS, SSLv2, weak SMB settings.

Nothing is rated Critical automatically; High is used only for clearly insecure protocols or confirmed script evidence.

## 6-8. Installation
Requirements: Python 3.9+, Nmap 7+.
```
pip install -r requirements.txt
```
**Install Nmap:**
* Windows: download the installer from https://nmap.org/download.html (tick "Add to PATH"), reopen the terminal.
* Ubuntu/Debian/Kali: `sudo apt install nmap`
* macOS: `brew install nmap`
* Check: `nmap --version`

## 9. Start the application
```
cd port_vulnerability_assessment
python app.py
```
Open http://127.0.0.1:5000 (the server listens on localhost only).

## 10. Perform an authorized scan
1. Enter a target such as `127.0.0.1` or your lab VM IP.
2. Tick the authorization checkbox and click **Start scan**.
3. Watch the progress steps; results appear when finished.

Targets must be inside `allowed_networks` in `config.json` (loopback and private ranges by default). A public IP is rejected. Only add a range there if you own it or have written permission.

## 11. Where the JSON files are created
`output/port_scan.json` and `output/vulnerabilities.json` (created/overwritten by each scan; also viewable/downloadable on the dashboard). A failed scan still writes both files with `"status": "failed"` and an `error` message, so other modules can always read them.

## 12. JSON fields
**port_scan.json -> scan_metadata:** `module`, `schema_version` (for integration), `target` (what you typed), `resolved_address`, `hostname`, `scan_time`, `scanner`, `status` (completed/failed), `nmap_version`, `duration_seconds`, `nse_scripts_used`, `notes`, `error` (only if failed).
**ports[]:** `port`, `protocol`, `state` (always open), `service`, `product`, `version`, `extra_info`, `tunnel` (ssl if TLS), `nse_results` (script name -> output).
**vulnerabilities.json -> scan_metadata:** same as above plus `total_findings`, `severity_summary`.
**findings[]:** `id`, `title`, `severity` (Informational/Low/Medium/High/Critical), `affected_port`, `protocol`, `service`, `evidence` (what Nmap actually reported), `description` (why it matters), `recommendation`, `confidence` (Low/Medium/High), `category` (exposure/version/configuration).

Read from another module:
```python
import json
ports = json.load(open("output/port_scan.json"))["ports"]
```

## 13. Limitations
* Version checks rely on banners, which can be wrong, hidden or back-ported.
* The baseline table is small; it is not a CVE database and does not replace tools such as OpenVAS or Nessus.
* TCP only; top 1000 ports by default; one host at a time; IPv4/IPv6 single addresses.
* Findings are "potential concerns" needing manual verification. No exploitation is performed.

## 14. Ethics and authorization
Scanning without permission can be illegal (e.g. Computer Misuse laws, the Indian IT Act 2000) and may disrupt systems. Scan only your own machines or labs. Safe lab targets: your own PC, a VM on a host-only network (e.g. Metasploitable 2, DVWA, OWASP Juice Shop), or `scanme.nmap.org` within Nmap's published rules (add it to `allowed_networks` only if you accept that).

## 15. Troubleshooting
| Message | Fix |
|---|---|
| Nmap is not installed or not in PATH | Install Nmap, reopen the terminal, check `nmap --version` |
| outside the allowed networks | Use a private/localhost target or edit `allowed_networks` (only for authorized systems) |
| hostname could not be resolved | Use the IP address |
| target did not respond | Check the VM is on, same network; set `"skip_host_discovery": true` if it blocks ping |
| scan timed out | Lower `top_ports` or set `"port_spec": "1-1024"` in `config.json` |
| permission problem | Check antivirus/firewall; this app uses `-sT` and needs no admin rights |
| Port 5000 in use | Change `"port"` in `config.json` |
| No open ports | Normal for a closed host; start a service (e.g. `python -m http.server 8080`) and scan again |

## Testing
**Automated** (Tests 3 and 4, plus parser/engine logic; Test 1 runs automatically if Nmap exists):
```
python -m unittest discover -s tests -v
```
**Manual tests**
* **Test 1 - localhost:** run `python -m http.server 8080` in another terminal, then set `"port_spec": "1-10000"` in `config.json` (optional) and scan `127.0.0.1`. Port 8080 should appear with an "HTTP without encryption" Informational finding.
* **Test 2 - lab machine:** start your VM (host-only network, e.g. 192.168.56.101), scan that IP. A deliberately vulnerable VM should show several services and findings.
* **Test 3 - invalid input:** try `abc!`, `192.168.1.0/24`, `8.8.8.8`, and an empty box; each shows a friendly error.
* **Test 4 - Nmap unavailable:** temporarily start the app with Nmap hidden (Linux/macOS: `PATH=/usr/bin/false-dir:$PATH` is unreliable, so simply rename the nmap binary or remove it from PATH), then scan; you should see "Nmap is not installed or not in PATH". The unit test `NmapMissingTest` proves this automatically.

## Sample JSON (structure only; real files come from real scans)
```json
{"scan_metadata": {"target": "192.168.56.101", "status": "completed"},
 "findings": [{"id": "FINDING-001", "title": "Unencrypted remote login service (Telnet)",
   "severity": "High", "affected_port": 23, "protocol": "tcp", "service": "telnet",
   "evidence": "Nmap service detection identified telnet on tcp/23.",
   "description": "Potential security concern: ...", "recommendation": "Disable Telnet and use SSH instead...",
   "confidence": "Medium", "category": "exposure"}]}
```

## How to Explain This Project in Viva
* **Port scanning:** knocking on a machine's numbered doors (ports) to see which answer.
* **Why check open ports?** Each open port is a possible entry point; unused ones should be closed.
* **Service:** the program listening behind a port, e.g. SSH on 22, a web server on 80.
* **Why identify versions?** Old versions may have known bugs; the version tells us what to check.
* **Vulnerability assessment:** a health check that lists possible weaknesses and how to fix them, without attacking.
* **Evidence:** the real data from the scan that justifies a finding, so nobody has to trust us blindly.
* **Severity:** ranks how urgent a finding is (Informational to Critical) so fixes are prioritised.
* **Recommendations:** a finding without advice is not useful; each one says what to do.
* **Why authorization?** Scanning others' systems without permission is illegal and can disrupt them; permission is what separates security work from attacking.
* **Weakness vs exploitation:** finding a weakness is noticing an unlocked window; exploiting it is climbing through. This project only notices and reports.

## Screenshot Procedure
Take every screenshot from a real run on your own/lab machine. Do not edit or fabricate them.
1. Terminal showing `python app.py` running (with the authorization line).
2. Dashboard home page (before scanning).
3. Target entered, authorization box ticked, notice visible.
4. Scan in progress (progress steps highlighted; take it quickly after clicking Start).
5. Completed scan with the summary tiles and severity summary.
6. Open ports/services table.
7. Findings with evidence and recommendations (scroll; capture several).
8. Invalid target error (e.g. `8.8.8.8`).
9. `output/port_scan.json` (open in an editor or via the View button).
10. `output/vulnerabilities.json`.
11. Folder view of `output/` showing both files with timestamps.
12. `python -m unittest discover -s tests -v` result in the terminal.
Add a caption with the target IP, date and a note that it is your own lab system.

## Authorization statement
This software is for educational use on systems you own or have explicit written permission to test. It contains no exploitation, stealth, evasion, credential attacks or denial-of-service features. You are responsible for how you use it.
