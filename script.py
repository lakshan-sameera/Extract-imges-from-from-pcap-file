from scapy.all import *
import os
import re

# Create output folder
output_dir = "extracted"
os.makedirs(output_dir, exist_ok=True)

# Load the PCAP file
packets = rdpcap("[FileName.pcap]")

# Image file signature patterns
image_signatures = {
    b"\xff\xd8\xff": "jpg",    # JPEG
    b"\x89PNG\r\n\x1a\n": "png",  # PNG
    b"GIF89a": "gif",           # GIF
}

def get_image_type(payload):
    for signature, ext in image_signatures.items():
        if signature in payload:
            return ext
    return None

# Combine HTTP payloads
sessions = packets.sessions()
img_counter = 0

for session in sessions:
    payload = b""
    for packet in sessions[session]:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload += packet[Raw].load

    # Attempt to locate image headers
    for signature, ext in image_signatures.items():
        found = [m.start() for m in re.finditer(re.escape(signature), payload)]
        for i, start in enumerate(found):
            end = payload.find(b"\r\n\r\n", start)
            if end == -1:
                end = len(payload)
            data = payload[start:end]
            if len(data) > 1000:  # Avoid false positives
                filename = os.path.join(output_dir, f"image_{img_counter}.{ext}")
                with open(filename, "wb") as f:
                    f.write(data)
                print(f"[+] Extracted: {filename}")
                img_counter += 1
