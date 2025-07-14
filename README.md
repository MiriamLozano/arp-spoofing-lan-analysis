# ARP Spoofing in Local Networks: Attack Simulation, Traffic Analysis, and Mitigation

## Description
This project examines the security risks inherent in Local Area Networks (LANs), with a focus on data interception through **ARP spoofing**. 

To achieve this, a virtual environment was built using Ubuntu 22.04. One Virtual Machine (VM) acts as the server, hosting a web service, while another VM serves as the client, accessing the website. 
To exploit LAN vulnerabilities, a VM running Kali Linux acts as the attacker, compromising network security and intercepting client-server communications. 


## Objective

The aim is to analyse the attacker’s effectiveness under different protocols, comparing the use of an insecure protocol **(HTTP)** with an encrypted one **(HTTPS)** and to discuss possible **mitigation** to protect and secure the network.

## 🌐 Network design
-	🖥️ `Ubuntu 22.04` Virtual Machine acting as a **server**, hosting a web service.
-	🖥️ `Ubuntu 22.04` Virtual Machine acting as a **client**, accessing the web.
-	⚔️ A `Kali Linux` Virtual Machine acting as an **attacker**, intercepting traffic between client and server using ARP spoofing.

The machines are set up as a **Local Network (LAN)** using static IP addresses.

## 🛠️ Technologies used
- Oracle VirtualBox
- WireShark
- Apache2 Web Server
- arpspoof

---

# Network configuration
Client and server communicate over a LAN. The first step is to configure the network and verify its connectivity using an ICMP ping.

Each machine was configured with its network adapter set to **‘Internal Network’**, using the same network name across all machines. This configuration simulates a Local Area Network, allowing the machines to communicate with each other in isolation.

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image002.png" alt="Internal network" />
</p>

To simplify the process, **static IP addresses** were assigned to both the client and the server. This was done by modifying the /etc/netplan/*.yaml file through the Ubuntu Terminal.
-	The **client** was assigned the IP address: `192.168.10.10/24`
-	The **server** was assigned the IP address: `192.168.10.11/24`

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image004.png" alt="Ip adresses" />
</p>

The connection between the client and the server was tested using the `ping` command. Both machines successfully responded to each other’s messages, confirming that they were connected to the same LAN.

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image006.png" alt="ping" />
</p>

# HTTP Server Configuration
Once the client and the server were connected to the same LAN, the server was configured to host a web service accessible to the client. This was achieved by installing **Apache2**, a tool that offers an **HTTP server**. 

HTTP was selected to demonstrate the **risks and vulnerabilities** in using non-encrypted protocols for data transmission and to show how easy it is for an attacker to intercept and steal sensitive information. 

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image008.png" alt="Apache2" />
</p>

Then, the client accesses the webpage through the `curl` command. 

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image010.png" alt="Curl" />
</p>


# ARP Spoofing in the LAN with HTTP protocol

### ARP spoofing  definition
**ARP Spoofing** is a type of *Man-in-the-middle attack (MitM)* that allows attackers to manipulate the ARP protocol on a LAN, enabling the interception of communication between network devices. 

**ARP** is responsible for mapping IP addresses to MAC addresses in a Local Area Network. In normal circumstances, devices on a network have an ARP table to know which MAC addresses correspond to each IP address. In this type of attack, the table is manipulated. An attacker sends forged ARP replies to other devices on the network, associating their own MAC address with the IP address of other devices. As a result, the targeted devices upload their ARP tables with incorrect information and begin sending network traffic to the attackers instead of the receiver. 

### Attack
Once the attacker is between two devices, they can intercept sensitive data, modify the traffic or launch other attacks.
At this point, it is assumed that the attacker has gained access to the network and is operating within the same LAN as the client and the server. Although the method of infiltration is not beyond the scope, the attacker could have access to the network by compromising a device or gaining unauthorised access. 

The network configuration for the attacker machine was set to simulate its presence on the same LAN as the client and the server. The IP address was set as 192.168.10.15. 
<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image012.png" alt="ipaddress" />
</p>

In order for the attacker not to be discovered, it is necessary to enable ‘IPv4 forwarding’. This means that the attacker will receive the traffic and forward it to the client, making the communication seem normal.

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image016.png" alt="ipv4forwarding" />
</p>

Then, the ARP spoofing attack is performed. 

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image018.png" alt="arpspoofing" />
</p>

### 📦 Data interception analysis

The tool used to analyse and intercept the network traffic is Wireshark. It allows the capture and analysis of network packets in real-time, providing information relative to origin and destination IP addresses, protocols used, packet longitude and other details.

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image020.png" alt="wireshark" />
</p>

The image above shows the communication flow in the Local Area Network captured by the attacker. 

The **client** initiates an **HTTP connection** using the `curl` command, sending a **TCP SYN package** to the **server**. However, the package is sent to the **attacker** due to the ARP spoofing attack. The attacker then forwards the SYN to the actual server.  In response, the server answers with a SYN-ACK that is intercepted again by the attacker and relayed to the client.

At this point, the attacker is now able to observe the entire data flow and exchange, being able to see, modify or save sensitive data without the client and server noticing. 

On the upper right, the HTML content of the web page is visible, as the communication is not encrypted using HTTP protocol. 

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image022.png" alt="wireshark2" />
</p>

# ARP Spoofing in the LAN with HTTPS protocol

Now, the **ARP spoofing attack** was executed using the **HTTPS protocol** instead of the HTTP protocol. An SSL certificate was generated and integrated into the server, making it more difficult for attackers to intercept the message, as it is encrypted.

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image026.png" alt="ssl" />
</p>

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image029.png" alt="ssl" />
</p>

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image036.png" alt="ssl" />
</p>

Now, the client accesses the page. When accessing the page, a warning will appear because the certificate is self-signed and not issued by a trusted certificate authority. For testing purposes, we will proceed by accepting the risk.

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image038.png" alt="website" />
</p>

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image040.png" alt="ssl" />
</p>

### Attack
After accessing the page from the client, we launch a new ARP spoofing attack to test the behaviour under HTTPS.

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image042.png" alt="arpspoofing" />
</p>

We analyze the traffic in Wireshark. As shown in the bottom right section, the message is encrypted, making it more difficult for an attacker to read its contents. This communication is significantly more secure than when using HTTP. 

However, the risk is not eliminated. Even though decrypting the message is harder, this type of attack can still be used as a starting point for more serious threats, such as server denial-of-service, message modification, and others.

<p align="center">
  <img src="https://github.com/MiriamLozano/arp-spoofing-lan-analysis/blob/main/assets/images/image044.png" alt="wireshark" />
</p>

# Possible risks of an ARP spoofing attack

### 🕵 Man-in-the-middle attack 
- credential theft
- Identity impersonation
- Tampering with data in transit

### 🚨 Session Hijacking
An attacker can steal session cookies or tokens and hijack a user's session.

### 🛡️ Denial of Service
The attacker can redirect traffic to a non-responsive IP address, causing a communication failure.

### 👿 DNS Spoofing
The attacker intercepts DNS queries and redirects the client to a malicious website, causing phishing attacks or malware installation.

# Mitigations

ARP spoofing can be prevented through the implementation of robust network security measures and best practices.

To protect against ARP spoofing attacks in a LAN, the following mitigation techniques should be considered:

- **Use Static ARP entries**:
For critical services and devices, using static ARP entries in the ARP table ensures their MAC addresses remain fixed so they cannot be spoofed.

- **Enable Dynamic ARP inspection**:
On switches, DAI is a secure tool that protects against ARP spoofing. It intercepts all ARP packets and validates them to a trusted IP-to-MAC address. If an ARP packet doesn't match, the packet is dropped.
  
- **Use encrypted protocols**:
It is essential to use protocols that ensure that even if a package is intercepted, it remains unreadable to the attacker. 
  
- **Network segmentation**:
Isolating critical devices from the rest of the network into VLANs limits the attacker's ability to reach them.
  
- **Monitor ARP Tables**:
  Changes in the ARP tables mean spoofing activity. Should be considered using monitoring tools that trigger alerts in those cases. 
  
- **Use Package filtering**
- **Use of firewalls**
- **Port security**:
Switches can be configured to only access a limited number of MAC addresses per port, helping detect ARP spoofing attacks.
- **Educate users**
Educating users is crucial to prevent social engineering attacks, and it reduces the chances of not noticing unusual network behaviour.
























