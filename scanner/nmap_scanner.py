"""Runs Nmap safely (no shell) and returns its XML output."""
import re
import shutil
import subprocess


class NmapError(Exception):
    """Raised with a friendly message when a scan cannot be completed."""


def build_command(nmap_path, address, ip_version, scan_cfg, scripts):
    """Build the Nmap command as a list (never a shell string).

    -sT  TCP connect scan (works without administrator rights)
    -sV  service and version detection
    -oX - XML output to stdout, which our parser reads
    Only non-destructive, non-intrusive NSE scripts are ever passed in.
    """
    timeout = int(scan_cfg.get("timeout_seconds", 300))
    cmd = [nmap_path, "-sT", "-sV", "--version-intensity", "5",
           "-" + scan_cfg.get("timing", "T3"), "-oX", "-",
           "--host-timeout", f"{max(30, timeout - 10)}s"]
    port_spec = str(scan_cfg.get("port_spec", "")).strip()
    if port_spec and re.fullmatch(r"[0-9,\-]+", port_spec):
        cmd += ["-p", port_spec]
    else:
        cmd += ["--top-ports", str(int(scan_cfg.get("top_ports", 1000)))]
    if ip_version == 6:
        cmd.append("-6")
    if scan_cfg.get("skip_host_discovery"):
        cmd.append("-Pn")
    if scripts:
        cmd += ["--script", ",".join(scripts), "--script-timeout", "30s"]
    cmd.append(address)
    return cmd


def run_scan(address, ip_version, config):
    """Scan one validated address. Returns {"xml", "scripts_used", "notes"}."""
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise NmapError(
            "Nmap is not installed or not in PATH. Install it from "
            "https://nmap.org/download and restart the application."
        )

    scan_cfg = config.get("scan", {})
    timeout = int(scan_cfg.get("timeout_seconds", 300))
    scripts = list(config.get("nse_scripts", [])) if scan_cfg.get("use_nse", True) else []
    notes = []

    # Second attempt runs without NSE if the scripts cause Nmap to fail.
    for attempt in range(2):
        cmd = build_command(nmap_path, address, ip_version, scan_cfg, scripts)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise NmapError(
                f"The scan timed out after {timeout} seconds. Try a smaller "
                "'top_ports' or 'port_spec' in config.json."
            )
        except PermissionError:
            raise NmapError("Permission denied while starting Nmap. Check file permissions.")
        except OSError as exc:
            raise NmapError(f"Could not start Nmap: {exc}")

        if proc.returncode == 0 and proc.stdout.strip():
            return {"xml": proc.stdout, "scripts_used": scripts, "notes": notes}

        err = (proc.stderr or "").strip()
        if scripts and attempt == 0 and re.search(r"NSE|script", err, re.I):
            notes.append("NSE scripts were unavailable; the scan used basic detection only.")
            scripts = []
            continue
        if re.search(r"root|permission|not permitted|privilege", err, re.I):
            raise NmapError(
                "Nmap reported a permission problem. Run the app with sufficient "
                "rights or check your firewall/security software."
            )
        raise NmapError(f"Nmap failed: {err[:300] or 'no error text returned'}")
    raise NmapError("Nmap did not return usable output.")
