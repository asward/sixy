"""Best-guess descriptions for commonly exposed ports.

Used to explain what an open port most likely is, alongside nmap's own
service/version fingerprint. Risk: critical / high / medium / low.
"""

PORTS = {
    20: ("FTP data", "Legacy file transfer; credentials sent in cleartext.", "high"),
    21: ("FTP", "Legacy file transfer; credentials sent in cleartext. Replace with SFTP.", "high"),
    22: ("SSH", "Remote shell. Use keys only, disable password + root login, consider fail2ban.", "medium"),
    23: ("Telnet", "Unencrypted remote shell, heavily botnet-targeted. Close it.", "critical"),
    25: ("SMTP", "Mail server. Open relays get abused; most ISPs block this anyway.", "medium"),
    53: ("DNS", "If this is a resolver, it can be abused for DDoS amplification.", "high"),
    80: ("HTTP", "Web server / reverse proxy. Fine if intentional; prefer redirect to HTTPS.", "low"),
    81: ("HTTP alt", "Often IP cameras or NVR web UIs.", "high"),
    88: ("Kerberos", "Domain auth service; should never be internet-facing.", "high"),
    110: ("POP3", "Mail retrieval, often unencrypted.", "medium"),
    111: ("rpcbind", "NFS/RPC portmapper. Should never be exposed.", "high"),
    135: ("MS RPC", "Windows RPC endpoint mapper. Never expose.", "critical"),
    139: ("NetBIOS/SMB", "Windows file sharing. Never expose.", "critical"),
    143: ("IMAP", "Mail retrieval, often unencrypted.", "medium"),
    443: ("HTTPS", "Web server / reverse proxy. Fine if intentional; keep it patched.", "low"),
    445: ("SMB", "Windows/Samba file sharing. Wormable history (WannaCry). Never expose.", "critical"),
    465: ("SMTPS", "Mail submission over TLS.", "medium"),
    500: ("IKE (IPsec)", "VPN key exchange (normally UDP).", "low"),
    548: ("AFP", "Apple file sharing / Time Machine. Don't expose.", "high"),
    554: ("RTSP", "Camera/NVR video stream. Often no or default auth.", "high"),
    587: ("SMTP submission", "Mail submission.", "medium"),
    631: ("IPP/CUPS", "Printer service. Don't expose.", "high"),
    873: ("rsync", "File sync daemon, sometimes unauthenticated.", "high"),
    993: ("IMAPS", "Mail retrieval over TLS.", "low"),
    995: ("POP3S", "Mail retrieval over TLS.", "low"),
    1080: ("SOCKS proxy", "Open proxies get abused fast.", "high"),
    1194: ("OpenVPN", "VPN endpoint. Fine if intentional.", "low"),
    1433: ("MS SQL", "Database. Never expose directly.", "critical"),
    1723: ("PPTP VPN", "Obsolete, broken VPN protocol. Replace with WireGuard.", "high"),
    1883: ("MQTT", "IoT message broker, often unauthenticated.", "high"),
    1900: ("UPnP/SSDP", "Router UPnP. Exposure means UPnP is misconfigured.", "high"),
    2049: ("NFS", "Network file system. Never expose.", "critical"),
    2375: ("Docker API (no TLS)", "Unauthenticated Docker = full host takeover. Close immediately.", "critical"),
    2376: ("Docker API (TLS)", "Docker remote API. Should not be internet-facing.", "high"),
    3000: ("Grafana / dev server", "Common for Grafana, Node apps, Gitea.", "medium"),
    3306: ("MySQL/MariaDB", "Database. Never expose directly.", "critical"),
    3389: ("RDP", "Windows Remote Desktop. Top ransomware entry point. Put behind VPN.", "critical"),
    4443: ("HTTPS alt", "Alternate HTTPS, often an admin UI.", "medium"),
    5000: ("Synology DSM / UPnP / dev", "Synology HTTP UI or Flask/dev servers.", "high"),
    5001: ("Synology DSM (HTTPS)", "NAS admin UI. Put behind VPN.", "high"),
    5060: ("SIP", "VoIP signalling; toll-fraud target.", "high"),
    5432: ("PostgreSQL", "Database. Never expose directly.", "critical"),
    5555: ("ADB", "Android Debug Bridge (TVs, boxes). Full device control.", "critical"),
    5900: ("VNC", "Remote desktop, often weak auth. Put behind VPN.", "critical"),
    6379: ("Redis", "Often unauthenticated; leads to RCE. Never expose.", "critical"),
    6443: ("Kubernetes API", "Cluster control plane.", "high"),
    6881: ("BitTorrent", "Torrent client listening port. Expected if you torrent.", "low"),
    7547: ("TR-069 (CWMP)", "ISP remote-management of your router. Usually ISP-controlled.", "medium"),
    8000: ("HTTP alt", "Dev servers, Portainer edge, various apps.", "medium"),
    8006: ("Proxmox VE", "Hypervisor admin UI. Put behind VPN.", "critical"),
    8080: ("HTTP alt / proxy", "Admin UIs, proxies, Tomcat, qBittorrent WebUI.", "medium"),
    8081: ("HTTP alt", "Admin UIs, NVRs.", "medium"),
    8096: ("Jellyfin/Emby", "Media server HTTP. Prefer reverse proxy with TLS.", "medium"),
    8123: ("Home Assistant", "Smart-home control. Prefer VPN or Nabu Casa.", "high"),
    8443: ("HTTPS alt", "Admin UIs (UniFi, routers, NAS).", "high"),
    8888: ("HTTP alt / Jupyter", "Jupyter gives code execution if exposed.", "high"),
    8920: ("Jellyfin/Emby HTTPS", "Media server HTTPS.", "medium"),
    9000: ("Portainer / MinIO", "Container admin = host control. Put behind VPN.", "critical"),
    9090: ("Cockpit / Prometheus", "Server admin or metrics with no auth.", "high"),
    9091: ("Transmission WebUI", "Torrent client UI.", "high"),
    9100: ("Printer (JetDirect) / node_exporter", "Raw printing or metrics. Don't expose.", "high"),
    9443: ("Portainer HTTPS", "Container admin = host control. Put behind VPN.", "critical"),
    10000: ("Webmin", "Server admin panel, history of RCEs.", "critical"),
    10250: ("Kubelet", "Can allow remote code execution in pods.", "critical"),
    11211: ("Memcached", "DDoS amplification and data leaks.", "critical"),
    25565: ("Minecraft", "Game server. Fine if intentional.", "low"),
    27017: ("MongoDB", "Database, frequently ransomed when exposed.", "critical"),
    32400: ("Plex", "Plex Media Server remote access. Normal if you enabled it.", "low"),
    51820: ("WireGuard", "VPN (UDP; won't appear in a TCP scan).", "low"),
}

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def describe(port: int, nmap_service: str = "") -> dict:
    if port in PORTS:
        name, note, risk = PORTS[port]
        return {"likely": name, "note": note, "risk": risk}
    svc = (nmap_service or "").rstrip("?")
    if svc in ("http", "http-proxy", "http-alt"):
        return {"likely": "Web service", "note": "Unrecognised web app on a non-standard port. Check what it is.", "risk": "medium"}
    if svc in ("https", "ssl", "ssl/http"):
        return {"likely": "TLS web service", "note": "Unrecognised TLS service. Check what it is.", "risk": "medium"}
    if svc == "ssh":
        return {"likely": "SSH (non-standard port)", "note": "Moving SSH doesn't secure it. Keys only.", "risk": "medium"}
    return {"likely": svc or "Unknown", "note": "Unrecognised service. Find which device/forward owns it.", "risk": "unknown"}
