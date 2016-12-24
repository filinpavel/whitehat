
* [Footprinting and Reconnaissance](#footprinting-and-reconnaissance)
* [Scanning Networks](#scanning-networks)
* [Enumeration](#enumeration)
* [System Hacking](#system-hacking)
* [Malware Threats](#malware-threats)
* [Sniffing](#sniffing)
* [Social Engineering](#social-engineering)
* [Denial-of-Service](#denial-of-service)
* [Session Hacking](#session-hacking)
* [Hacking Webservers](#hacking-webservers)
* [Hacking Web Applications](#hacking-web-applications)
* [SQL Injection](#sql-injection)
* [Hacking Wireless Networks](#hacking-wireless-networks)
* [Hacking Mobile Platforms](#hacking-mobile-platform)
* [Evading IDS, Firewalls and Honeypots](#evading-ids-firewalls-and-honeypots)
* [Cloud Computing](#cloud-computing)
* [Cryptography](#cryptography)


## Footprinting and Reconnaissance
*  [Footprinting](https://en.wikipedia.org/wiki/Footprinting)
* Objectives: 
  * Collect Network Information
  * Collect System Information
  * Collect Organisation's Information
* Methods:
  * Footprinting through Search Engines
    * Search for Public and Restricted Wesites
  * Operating System Identification
     * Tools: [Netcraft](http://netcraft.com), [SHODAN](http://shodan.io)
  * Get Location Information:
     * Tools: [Google Maps](https://maps.google.com), [Yandex Panorama](https://yandex.ru/maps) 
  * Social Networking Sites (SNS) and People Search Services
     * Tools: Linkedin, Facebook, Twitter,  Vkontakte, Odnoklassniki
  * Collect Financial Information and [Financial Intelligence](https://en.wikipedia.org/wiki/Financial_intelligence)
  * Searching through Job Sites
     * Tools: Linkedin, Monster.com, HH.ru, zarplata.ru
  * Footprinting using [Google Dorks](https://en.wikipedia.org/wiki/Google_hacking)
    * Resources: [Powersearching](http://www.powersearchingwithgoogle.com/), [Google Hacking Database](https://www.exploit-db.com/google-hacking-database/)
  * Footprinting using Social Media
  * [Competitive intelligence](https://en.wikipedia.org/wiki/Competitive_intelligence)
  * Website footprinting
    * Tools: [OWASP Zaproxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project), [Burp Suite](https://portswigger.net/burp/), WebSpiders, HTTrack, GNU Wget
  * Email footprinting
  * [WHOIS](https://en.wikipedia.org/wiki/WHOIS) footprinting
    * Resources: [RU-CENTER](https://www.nic.ru/whois/en/)
  * DNS footprinting
    * Tools: DNSstuff
  * Network footprinting: [TCP/IP stack fingerprinting](https://en.wikipedia.org/wiki/TCP/IP_stack_fingerprinting)
    * Tools: [Qualys SSl LAB](http://ssllab.com), traceroute, Nmap, p0f
  * Footprinting using Social Engineering
 * Tools: [Maltego](https://www.paterva.com/web7/buy/maltego-clients.php), [recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng), FOCA, [Metagoofil](http://www.edge-security.com/metagoofil.php)
 * Resources: [Aewsome-OSINT](https://github.com/jivoi/awesome-osint)
 
## Scanning Networks
* Objectives:
  * Discover IP address and open [ports](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
  * Discover [operating system](https://en.wikipedia.org/wiki/Operating_system)
  * Discover services runing
  * Discover [vulnerabilities](https://en.wikipedia.org/wiki/Vulnerability_(computing))
* Methods: 
  * [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) Scanning, [Ping Sweep](https://en.wikipedia.org/wiki/Ping_sweep)
  * [SSDP](https://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol) Scanning
  * TCP Connect/Full Open Scan
  * [Stealth Scan (Half-open Scan)](https://en.wikipedia.org/wiki/TCP_half-open)
  * Inverse TCP Flag Scan
  * [Xmas Scan](https://en.wikipedia.org/wiki/Christmas_tree_packet)
  * [ACK Flag Probe Scan](https://en.wikipedia.org/wiki/Port_scanner#ACK_scanning)
  * [IDLE Scan](https://en.wikipedia.org/wiki/Idle_scan)
  * [UDP Scanning](https://en.wikipedia.org/wiki/Port_scanner#UDP_scanning)
* Tools: [Nmap](), [Hping](), [nping](), [scapy](https://github.com/secdev/scapy), [SolarWinds Engineers Toolset](http://www.solarwinds.com/engineers-toolset), amap, SPARTA, Nessus, OpenVAS, Microsoft Baseline Security Analyzer
* Resources: [Qualys FreeScan](https://freescan.qualys.com/freescan-front/)

## Enumeration
*
*
*
*

## System Hacking
*
*
*
*

## Malware Threats
*
*
*
* Resources: [Awesome-Malware-Analysis](https://github.com/rshipp/awesome-malware-analysis)

## Sniffing
*
*
*
* Resources:

## Social Engineering
*
*
*
*

## Denial-of-Service
*
*
*
*

## Session Hacking
* [Session hijacking](https://en.wikipedia.org/wiki/Session_hijacking)
* [Spoofing](https://en.wikipedia.org/wiki/Spoofing_attack)
* Application Level Session hijacking:
 * [Session fixation](https://en.wikipedia.org/wiki/Session_fixation)
 * [Cross-site scripting (XSS)](https://en.wikipedia.org/wiki/Cross-site_scripting)
 * [Cross-site Request Forgery](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
 * [Browser hijacking](https://en.wikipedia.org/wiki/Browser_hijacking)
 * [Session poisoning](https://en.wikipedia.org/wiki/Session_poisoning)
 * [Man-in-the-browser](https://en.wikipedia.org/wiki/Man-in-the-browser)
 * [Man-in-the-middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)
 * [Session Replay](https://en.wikipedia.org/wiki/Session_replay)
* Network-level Session Hijacking:
 * [IP Spoofing](https://en.wikipedia.org/wiki/IP_address_spoofing)
 * [Packet Sniffing](https://en.wikipedia.org/wiki/Packet_analyzer)
 * TCP/IP Hijacking
 * UDP Hijacking
 * Blind Hijacking
 * [ARP Spoofing](https://en.wikipedia.org/wiki/ARP_spoofing)
* [IPSec](https://en.wikipedia.org/wiki/IPsec)
* Tools: [OWASP Zaproxy](https://github.com/zaproxy/zaproxy), [Burp Suite](https://portswigger.net/burp/), [Firebug](https://developer.mozilla.org/en-US/docs/Tools), [Cain and Abel](http://www.oxid.it/cain.html), [Ettercap](https://ettercap.github.io/ettercap/), [sslstrip](https://github.com/moxie0/sslstrip),[Websploit](http://sourceforge.net/projects/websploit/), DroidSheep, DroidSniff

## Hacking Webservers
*
*
*
*

## Hacking Web Applications
*
*
*
* Resources: [Awesome-Web-Hacking](https://github.com/infoslack/awesome-web-hacking)

## SQL Injection
* [SQLi](https://en.wikipedia.org/wiki/SQL_injection)
* 
*
* Tools: [SQLmap](http://sqlmap.org/)

## Hacking Wireless Networks
*
*
*
*

## Hacking Mobile Platforms
*
*
*
* Resources: [Android-Security-Awesome](https://github.com/ashishb/android-security-awesome)

## Evading IDS, Firewalls and Honeypots
*
*
*
* Resources: [Awesome-Honeypots](https://github.com/paralax/awesome-honeypots)

## Cloud Computing
*
*
*
*

## Cryptography
* [Cryptography](https://en.wikipedia.org/wiki/Cryptography)
 * Objectives: Confidentiality, [Integrity](https://en.wikipedia.org/wiki/Data_integrity), [Authenication](https://en.wikipedia.org/wiki/Authentication), [Non-repudiation](https://en.wikipedia.org/wiki/Non-repudiation)
 * Types: [Asymmetric](https://en.wikipedia.org/wiki/Public-key_cryptography), [Symmetric](https://en.wikipedia.org/wiki/Symmetric-key_algorithm)
* [Data Encryption Standart (DES)](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
* [Advanced Encryption Standart (AES)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
 * Tools: [ccrypt](http://ccrypt.sourceforge.net/), [WinAES](https://github.com/yunzhu-li/winaes)
* [RC4](https://en.wikipedia.org/wiki/RC4), [RC5](https://en.wikipedia.org/wiki/RC5), [RC6](https://en.wikipedia.org/wiki/RC6) Algorithms
* [Digital Signature Algorithm (DSA)](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
* [Rivest Shamir Adleman (RSA)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
* [Message Digest Function (MD5)](https://en.wikipedia.org/wiki/MD5)
* [GOST (cifer)](https://en.wikipedia.org/wiki/GOST_(block_cipher))
 * Tools: MD5 calculator, [CrypTool](https://www.cryptool.org/en/), HahsCalc, [HashDroid](https://play.google.com/store/apps/details?id=com.hobbyone.HashDroid)
* [Secure](https://en.wikipedia.org/wiki/SHA-1) [Hashing](https://en.wikipedia.org/wiki/SHA-2) [Algorithm](https://en.wikipedia.org/wiki/SHA-3) (SHA)
* [Secure Shell (SSH)](https://en.wikipedia.org/wiki/Secure_Shell)
 * Tools: [OpenSSH](http://www.openssh.com/), [PuTTY](http://www.chiark.greenend.org.uk/~sgtatham/putty/), [SecureCRT](https://www.vandyke.com/products/securecrt/index.html), [WinSCP](https://winscp.net/eng/index.php)
* [Pretty Good Privacy (PGP)](https://en.wikipedia.org/wiki/Pretty_Good_Privacy)
 * Tools: [GNU Privacy Guard](https://www.gnupg.org/)
* [Public Key Infrastructure (PKI)](https://en.wikipedia.org/wiki/Public_key_infrastructure)
 * [Digital certificate](https://en.wikipedia.org/wiki/Public_key_certificate)
 * [Certificate Authority (CA)](https://en.wikipedia.org/wiki/Certificate_authority)
 * [Validation Authority](https://en.wikipedia.org/wiki/Validation_authority)
 * [Self-signed certificate](https://en.wikipedia.org/wiki/Self-signed_certificate)
* [Secure Sockets Layer (SSL)](https://en.wikipedia.org/wiki/Transport_Layer_Security)
 * Tools: [OpenSSL](https://www.openssl.org/), [GnuTLS](http://gnutls.org/), [LibreSSL](http://www.libressl.org/), [stunnel](https://www.stunnel.org/index.html), [Keyczar](https://github.com/google/keyczar)
* [Disk Encryption](https://en.wikipedia.org/wiki/Disk_encryption)
 * Tools: [VeraCrypt](https://sourceforge.net/projects/veracrypt/), []()
* Case styudy: [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed), [Poodle](https://en.wikipedia.org/wiki/POODLE)
* Resources: [Awesome-Cryptography](https://github.com/sobolevn/awesome-cryptography)

