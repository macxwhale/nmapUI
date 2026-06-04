import subprocess
import xml.etree.ElementTree as ET

SCAN_PROFILES = {
    "quick": ["nmap", "-F"],
    "service": ["nmap", "-sV"],
    "os": ["nmap", "-O"],
    "deep": ["nmap", "-A"],
    "vuln": ["nmap", "--script", "vuln"]
}

def run_nmap(target, profile):
    if profile not in SCAN_PROFILES:
        raise ValueError(f"Invalid scan profile: {profile}")
    
    # We use -oX - to output XML to stdout
    cmd = SCAN_PROFILES[profile] + ["-oX", "-", target]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(f"Nmap failed: {result.stderr}")

    return result.stdout

def parse_nmap_xml(xml_data):
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return {"error": "Invalid XML data"}

    results = []

    for host in root.findall("host"):
        addresses = host.findall("address")
        ip = "unknown"
        for addr in addresses:
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        
        ports = []
        for port_elem in host.findall(".//port"):
            port_id = port_elem.get("portid")
            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"
            
            service_elem = port_elem.find("service")
            service_name = service_elem.get("name") if service_elem is not None else "unknown"
            
            ports.append({
                "port": port_id,
                "state": state,
                "service": service_name
            })

        results.append({
            "ip": ip,
            "ports": ports
        })

    return results
