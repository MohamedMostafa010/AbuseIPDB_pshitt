======
MODIFIED PSHITT
======

Note: Forked Version with AbuseIPDB Integration
===============================================

This repository is a fork of the original `pshitt <https://github.com/regit/pshitt>`_ project.  
It extends the functionality by integrating with `AbuseIPDB <https://www.abuseipdb.com/>`_  
to check the reputation of an attacker's IP address before logging credentials.  
This enhancement provides additional insights into potential threats, allowing users  
to identify malicious sources more effectively.

Introduction
============

pshitt (for Passwords of SSH Intruders Transferred to Text) is a lightweight  
fake SSH server designed to collect authentication data sent by intruders.  
It captures usernames, passwords, and source IPs used in SSH brute-force attacks  
and writes the extracted data to a JSON file.

This fork introduces **AbuseIPDB integration**, which enables real-time  
threat intelligence by checking the attacker's IP address reputation before  
storing the credentials.

pshitt is written in Python and uses ``paramiko`` to implement the SSH layer.

Features
========
- **Fake SSH Server**: Captures brute-force attack credentials.
- **JSON Output**: Logs attacker data in structured JSON format.
- **AbuseIPDB Integration**: Checks attacker IP reputation before logging.
- **Multi-threading Support**: Handles multiple connections efficiently.
- **Log Analysis Compatibility**: Easily integrates with tools like Splunk and Logstash.

Installing pshitt
=================

Install Dependencies ::

  sudo apt-get update -y
  sudo apt-get install -y git python3 python3-pip python3-dev libssl-dev libffi-dev build-essential python3-venv python3-daemon python3-pycryptodome python3-paramiko python3-zope.interface

Install From Source ::

  git clone https://github.com/MohamedMostafa010/AbuseIPDB_pshitt.git
  cd AbuseIPDB_pshitt

NOTE: If you are installing from source, ensure you install the required dependencies:  
``paramiko``, ``python-daemon``, and ``requests`` (for AbuseIPDB integration).

Running pshitt
==============

Disabling SSH Service in the Entire System (Optional, if you do not need SSH for your remote access) ::

  sudo systemctl disable ssh.socket
  sudo systemctl stop ssh.socket
  sudo systemctl disable ssh
  sudo systemctl stop ssh

If you installed from source, go into the source directory and run (You can change the specified port '22', and also captured credentials file name and path)::

  chmod +x modifiedpshitt.py
  sudo ./modifiedpshitt.py -p 22 -o /home/azureuser/credentials.json

This will run a fake SSH server listening on **port 22**, capturing authentication  
data sent by attackers. Each login attempt is logged in JSON format,  
including AbuseIPDB results ::

    {
      "username": "root",
      "password": "password123",
      "src_ip": "156.214.155.185",
      "src_port": 12345,
      "timestamp": "2023-10-10T12:34:56.789012",
      "software_version": "SSH-2.0-OpenSSH_7.6p1",
      "cipher": "aes256-ctr",
      "mac": "hmac-sha2-256",
      "try": 1,
      "abuseipdb": {
        "ipAddress": "156.214.155.185",
        "isPublic": true,
        "ipVersion": 4,
        "isWhitelisted": null,
        "abuseConfidenceScore": 0,
        "countryCode": "EG",
        "usageType": "Fixed Line ISP",
        "isp": "TE Data",
        "domain": "tedata.net",
        "hostnames": ["host-156.214.185.155-static.tedata.net"],
        "isTor": false,
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": null
      }
    }


Full options are available via '-h' option ::

 usage: modifiedpshitt [-h] [-o OUTPUT] [-k KEY] [-l LOG] [-p PORT] [-t THREADS] [-v] [-D] [-a API_KEY]
 
 Passwords of SSH Intruders Transferred to Text
 
 optional arguments:
   -h, --help            show this help message and exit
   -o OUTPUT, --output OUTPUT
                         File to export collected data
   -k KEY, --key KEY     Host RSA key
   -l LOG, --log LOG     File to log info and debug
   -p PORT, --port PORT  TCP port to listen to
   -t THREADS, --threads THREADS
                         Maximum number of client threads
   -v, --verbose         Show verbose output, use multiple times to increase verbosity
   -D, --daemon          Run as Unix daemon
   -a API_KEY, --abuseipdb API_KEY
                         AbuseIPDB API Key (optional)

Using pshitt Data
=================

As the format is JSON, it is easy to use the data in security tools such as **Splunk**  
or **Logstash** for further analysis.

Here's a sample **Logstash** configuration to parse pshitt logs ::

 input {
    file {
       path => [ "/var/log/pshitt.log" ]
       codec =>   json
       type => "json-log"
    }
 }

 filter {
     # Use the correct timestamp field
     if [type] == "json-log" {
         date {
             match => [ "timestamp", "ISO8601" ]
         }
     }

     # Apply GeoIP lookup on attacker IP addresses
     if [src_ip]  {
         geoip {
             source => "src_ip"
             target => "geoip"
             add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
             add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
         }
         mutate {
             convert => [ "[geoip][coordinates]", "float" ]
         }
     }

     # Categorize attacks based on AbuseIPDB risk score
     if [abuseipdb_score] >= 75 {
         mutate {
             add_tag => [ "high-risk" ]
         }
     } else if [abuseipdb_score] >= 50 {
         mutate {
             add_tag => [ "medium-risk" ]
         }
     } else {
         mutate {
             add_tag => [ "low-risk" ]
         }
     }
 }

 output {
   elasticsearch {
        hosts => ["localhost"]
        index => "pshitt-attacks"
   }
 }

Basically, it is enough to specify that the ``pshitt.log`` file follows JSON format  
so that tools like **Elasticsearch**, **Kibana**, or **SIEM solutions** can process the data.

Contributing
============

Contributions are welcome! If you have suggestions or improvements, feel free to open a  
pull request or issue on the repository.

License
=======

This project is released under the MIT License.

