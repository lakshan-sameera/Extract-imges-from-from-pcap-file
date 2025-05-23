🧰 Tools and Libraries Used
  Scapy: For reading and processing the PCAP file.
  OS: For directory handling.
  re (Regular Expressions): To locate binary signatures within HTTP data.

⚙️ How It Works
Create an Output Directory:
  Creates a folder named extracted to store the recovered images.
  
Load the PCAP File:
  Reads the file security-footage-1648933966395.pcap using rdpcap.
  
Define Image File Signatures:
  Maps known image file "magic numbers" to their respective file types:
    JPEG: \xff\xd8\xff
    PNG: \x89PNG\r\n\x1a\n
    GIF: GIF89a

Reconstruct HTTP Payloads:
  For each TCP session, it combines all Raw payloads into a single binary blob.

Search for Image Signatures:  
  Scans the payload for occurrences of known image signatures.
  Extracts data starting at the signature until the next HTTP header end (\r\n\r\n) or payload end.
  Saves data longer than 1000 bytes to avoid false positives.

Write Images to Disk:
  Detected image segments are saved as image_0.jpg, image_1.png, etc., inside the extracted folder.

✅ Output
A list of extracted image files saved locally.
