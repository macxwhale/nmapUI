import subprocess
import xml.etree.ElementTree as ET

SCAN_PROFILES = {
    "quick": ["nmap", "-F"],
    "service": ["nmap", "-sV"],
    "os": ["nmap", "-O"],
    "deep": ["nmap", "-A"],
    "vuln": ["nmap", "--script", "vuln"],
    "comprehensive": ["nmap", "-sS", "-sV", "-O", "-sC", "--traceroute"]
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
        # Some scans return non-zero if some hosts are down, but XML might still be valid
        # However, for now we treat it as failure if it's not 0 or if there's significant stderr
        if not result.stdout:
            raise RuntimeError(f"Nmap failed: {result.stderr}")

    return result.stdout

def parse_nmap_xml(xml_data):
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return {"error": "Invalid XML data"}

    results = []

    for host in root.findall("host"):
        # Address information
        addresses = host.findall("address")
        ip = "unknown"
        mac = None
        vendor = None
        for addr in addresses:
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                ip = addr.get("addr")
            elif addr_type == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        
        # OS information
        os_matches = []
        for os_elem in host.findall(".//osmatch"):
            os_matches.append({
                "name": os_elem.get("name"),
                "accuracy": os_elem.get("accuracy")
            })

        # Ports and Services
        ports = []
        for port_elem in host.findall(".//port"):
            port_id = port_elem.get("portid")
            protocol = port_elem.get("protocol")
            
            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"
            
            service_elem = port_elem.find("service")
            service_info = {
                "name": "unknown",
                "product": "",
                "version": "",
                "extrainfo": ""
            }
            if service_elem is not None:
                service_info["name"] = service_elem.get("name", "unknown")
                service_info["product"] = service_elem.get("product", "")
                service_info["version"] = service_elem.get("version", "")
                service_info["extrainfo"] = service_elem.get("extrainfo", "")

            # Script output
            scripts = []
            for script_elem in port_elem.findall("script"):
                scripts.append({
                    "id": script_elem.get("id"),
                    "output": script_elem.get("output")
                })
            
            ports.append({
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": service_info,
                "scripts": scripts
            })

        # Host scripts
        host_scripts = []
        for script_elem in host.findall("hostscript/script"):
            host_scripts.append({
                "id": script_elem.get("id"),
                "output": script_elem.get("output")
            })

        # Traceroute
        trace = []
        for hop in host.findall("trace/hop"):
            trace.append({
                "hop": hop.get("ttl"),
                "ip": hop.get("ipaddr"),
                "rtt": hop.get("rtt"),
                "host": hop.get("host")
            })

        results.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "os_matches": os_matches,
            "ports": ports,
            "host_scripts": host_scripts,
            "trace": trace
        })

    return results
