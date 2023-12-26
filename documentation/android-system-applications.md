# Android System Applications

The Android operating system, widely used in mobile devices, is susceptible to various security threats at the application layer. This document explores common security challenges, potential threats, and recommended mitigations for safeguarding the system applications layer of Android OS. Understanding and addressing these security concerns are crucial for both users and developers to ensure a robust and secure mobile ecosystem.



## Malware

Malware is malicious software that is designed to cause unintentional harm to the system. Malware can evade security
mechanisms, collect sensitive user information, display unnecessary advertisements, or can interrupt with the normal functioning of the mobile device. Different types of mobile malware are the Trojans, backdoors, ransomware, spyware, adware, etc. [[1]](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94)

### Threats

- *Trojan* is a type of malware, which does not self-replicate. To avoid detection, Trojans are generally masked as legitimate software. Trojan can enter into the system via numerous vectors, such as navigating untrusted websites (drive-by-download), by clicking attachments in phishing emails, other forms of social engineering, etc. Trojan can steal sensitive user information, or can alter the data.
- *Ransomware* is type of malicious software, which restricts the access to the system resources and extorts money from the victims. Most popular ransomware in mobile platform is crypto-ransomware, which encrypts files of a system thereby restricting the users to access the files. Attackers then demand ransom for the key used to decrypt the files so as to resume the access.
- *Backdoor* is a malware that evades the authentication mechanism of the system. As a result, it can remotely access the database and file systems. Backdoor installation requires administrator privileges by rooting Android devices and jailbreaking Apple devices.
- *Spyware* is unwanted software that infiltrates your computing device, stealing your internet usage data and sensitive information. Spyware is classified as a type of malicious  software designed to gain access to or damage your computer, often without your knowledge. Spyware gathers your personal information and relays it to advertisers, data firms, or external users. [[1]](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94)

### Attacks [TODO]

- Malicious software distributed through third-party app stores.
- Unintentional installation of fake or compromised apps.

### Mitigations

- A *device firewall* is a software application that restricts certain types of access to and from the networks to which a system is connected. Android ships with the iptables firewall application like many other Linux distributions, although it is not configured with any rules by default. Configuring the firewall for Android devices could be accomplished based on network ports used or by UID/GID. In either case, a firewall control application could be written to afford the user control over how to grant network access to applications.
- *Security Enhanced Linux* (SELinux) is a  system application that provides mandatory access control and other security features for Linux systems. The SELinux project page contains an up to date list of implemented features, some of which include file-based context labels, labels for app installations, and the ability to create and manage SELinux policies. These features constrict almost any process or file on the device to actions based on the policy in effect, improving the effects of app sandboxing and putting controls in place around system processes.
- An application whitelist or blacklist application can serve a multitude of purposes in Android security. This proposed application would simply allow or deny application installation based on an installation list. This list can be used to identify apps that should not be installed on the device, or to allow specific apps to be installed or updated.
- Android's security model is comprised of two main
components: the permission system and application sandboxing. While the majority of malware simply requests permissions that are unneeded, it remains a possibility that a crafted application can leverage specific API calls while requesting permissions that seem legitimate, thereby providing access to the target data while deceiving the user into accepting the permission as it is portrayed. In order to get closer to the paradigm of "least permission," permission requests should be reduced to granting access to very small quantities of API calls, to minimize the potential for abusing permission requests. [[2]](https://sci-hub.se/10.1109/ictc.2016.7763562)



## Phishing Attacks

Phishing is a type of online identity theft in which sensitive information is obtained by misleading people to access a malicious webpage. Human behavior is strongly associated with technology, and phishing is solely based on social engineering, which relies on exploiting human vulnerability in order to trick the victim into providing sensitive credentials. Thus, phishing is one of the forms that social engineering can take. One of the main methods that mobile phishing has been applied is through developing a malicious application that is a copycat of a legitimate one. [[3]](https://sci-hub.se/10.1109/innovations.2014.6987555)

### Threats

- Fake system updates - attackers may send fake system update notifications that mimic the official Android update prompts. Users might unknowingly download and install malicious software, giving attackers unauthorized access to their devices.
- System app impersonation - phishers may create fake versions of system apps (e.g., settings, email, messaging) and trick users into installing them. Once installed, these apps may capture sensitive information, such as login credentials and personal data.
- Malicious app permissions - phishing attacks might involve deceptive apps that request unnecessary permissions during installation. Users who grant these permissions inadvertently expose their devices to potential data theft or unauthorized access.
- Credential harvesting - attackers may use phishing techniques to trick users into entering their login credentials into fake login screens that resemble legitimate system apps. Stolen credentials can be used for unauthorized access to various accounts and services.
- SMS phishing (Smishing) - phishers may send SMS messages containing malicious links, tricking users into clicking on them. These links may lead to fake websites that mimic legitimate system apps, aiming to capture sensitive information.
- Social engineering attacks - phishers may use social engineering tactics, such as fake support calls or messages claiming to be from a trusted source (e.g., the device manufacturer or mobile carrier). Users may be coerced into providing sensitive information or taking actions that compromise their device security. [[3]](https://sci-hub.se/10.1109/innovations.2014.6987555)

### Attacks [TODO]

- Creation of fake versions of popular apps to trick users.
- Deceptive websites or communication channels imitating legitimate sources.

### Mitigations

- Using official apps - users should only download official apps from the app stores.
- User training - user training is very important to prevent users clicking unknown links.
- Safer browsers - browsers with security features installed (such as Chrome mobile) eliminates malware and phishing sites to protect users.
- Bookmarks - bookmarks eliminate typos when typing URLs. Since it is hard to see the URL bar completely, bookmarking is a good solution to eliminate landing on unwanted pages.
- More controls by app stores: Vendors should take more steps before letting developers uploading their apps for the public.
- Security solutions: Just as security companies have anti-virus programs for desktops, now many also have mobile security solutions. Those programs eliminate malicious activity on mobile devices. [[4]](https://www.scirp.org/html/5-7800290_57634.htm)



## Data Leakage

When an application lands on the market, it becomes available to be used by everyone. This means that it can be tested and analyzed under all possible conditions. Every internal element of an app should share the necessary information to perform a specific task without any data leakage. This leakage can occur due to vulnerabilities, misconfigurations, or malicious activities and may lead to the exposure of sensitive user data to unauthorized entities. In order to recognize possible data leakages, two well-known approaches can be used: static and dynamic analysis. Static analysis is based on the examination of an application without the execution of it. Dynamic analysis, instead, relies on the execution of the applications. [[5]](https://www.hindawi.com/journals/misy/2018/6020461/)

### Threats

- Insecure data storage - sensitive data is stored on the device in an insecure manner, it may be susceptible to unauthorized access or extraction.
- Improper permissions handling - system applications request and are granted excessive or unnecessary permissions, it may result in the unintentional exposure of sensitive data.
- Vulnerabilities in system components - security vulnerabilities in system-level components can be exploited by attackers to gain access to sensitive information.
- Inadequate encryption - data transmitted between system applications or stored on the device is not properly encrypted, it may be intercepted and accessed by unauthorized parties.
- Weak authentication mechanisms - the authentication mechanisms used by system applications are weak, it may enable unauthorized users to gain access to sensitive data. [[5]](https://www.hindawi.com/journals/misy/2018/6020461/)

### Attacks [TODO]

- Exploitation of poorly implemented data storage mechanisms.
- Unauthorized retrieval of sensitive information from compromised apps.

### Mitigations

- Secure coding practices - developers should follow secure coding practices to prevent vulnerabilities in system applications. This includes input validation, proper error handling, and avoiding the use of deprecated or insecure functions.
- Data encryption - ensure that sensitive data is encrypted during transmission and storage. Use strong encryption algorithms and enforce encryption for sensitive data stored on the device.
- Least privilege principle - follow the principle of least privilege, ensuring that system applications only request and are granted the minimum permissions necessary for their functionality. Limiting permissions reduces the potential impact of a compromised application.
- Regular security audits - conduct regular security audits of system applications to identify and address vulnerabilities. This includes code reviews, static analysis, and dynamic testing.
- Update and patch management - keep the Android OS and system applications updated with the latest security patches. Timely updates help address known vulnerabilities and strengthen the overall security of the system.
- Implement secure authentication - use strong authentication mechanisms for system applications to prevent unauthorized access. Implement measures such as biometric authentication and two-factor authentication where appropriate.
- Secure communication protocols - ensure that secure communication protocols (e.g., HTTPS) are used for transmitting data between system applications and servers. Avoid using insecure protocols that may expose data to interception.
- User education - educate users about security best practices, such as avoiding the installation of apps from untrusted sources, being cautious with app permissions, and keeping their devices updated.
- Implement secure storage - store sensitive data securely on the device, utilizing encryption and secure storage practices. Avoid storing sensitive information in plaintext or in locations accessible to unauthorized applications.
- Monitor and respond to anomalies - implement monitoring mechanisms to detect unusual or unauthorized activities. Develop response plans to address security incidents promptly when detected. [[6]](https://sci-hub.se/10.1109/sp.2019.00009)



## Man-in-the-Middle (MitM) Attacks

Mobile applications usually communicate to remote servers for their operations using the HTTP protocol. This makes it possible for others to interrupt data or the HTTPS protocol, which makes it difficult, if not impractical, to intercept data. The Android platform offers methods and libraries to communicate with the server by the use of these secured network protocols, thus underpinning the Public-Key Infrastructure (PKI). However, despite the existence of Security protocols, the inappropriate use of the Android’s platform secured socket layer libraries might expose the applications to MitM attacks. During MitM attacks, traffic is usually interrupted and a spoofed certification is given to the client to mimic the server. If successful, MitM attacks might convince the customer to reveal their personal login details and other confidential
information to the MitM attacker, since the attack permits communication between the server and the client to be interrupted and read unencrypted. MitM attacks are normally executed on controlled Wi-Fi access points. Moreover, during an attack, the network traffic is usually captured for analysis. [[7]](https://sci-hub.se/10.1109/ccc.2016.15)

### Threats

- Data interception - an attacker intercepts communication between the Android device and a server, capturing sensitive data such as login credentials, personal information, or financial details.
- Session hijacking - attackers can hijack user sessions by stealing session tokens or cookies, allowing them to impersonate the user and gain unauthorized access to protected resources.
- Credential spoofing - the attacker may present a fake login interface to the user, tricking them into entering their credentials. The attacker then uses these credentials to access the genuine application or service.
- Tampering with data - the attacker modifies data exchanged between the Android device and the server, leading to the potential alteration of information or the introduction of malicious content.
- Injection attacks - attackers inject malicious code or scripts into the communication stream between the Android device and the server, leading to the execution of arbitrary code on the device.
- Malicious app updates - attackers may intercept the update process for applications and deliver malicious updates, compromising the security of the application and the device.
- DNS spoofing - manipulating the Domain Name System (DNS) responses to redirect the Android device to malicious servers, leading to communication with unauthorized or malicious entities.
- SSL stripping - attackers may downgrade secure HTTPS connections to unencrypted HTTP, making it easier to intercept and manipulate the data exchanged between the device and the server. [[8]](https://sci-hub.se/10.1109/ccc.2016.15)

### Attacks [TODO]

- Network eavesdropping and packet sniffing.
- Use of fake Wi-Fi hotspots and compromised network devices.

### Mitigations

- Avoiding WiFi associations that aren't password encrypted.  
- Paying consideration regarding browser warnings reporting a site as being unsecured.
- Immediately logging out of a protected application when it's not in utilize.
- Not using open systems (e.g., cafés, lodgings) when conducting sensitive financial exchanges.
- Using antivirus frameworks that furnishes its clients with a streamlined end-to-end SSL/TLS encryption, as a component of its suite of security administrations. [[8]](https://www.researchgate.net/publication/330249434_Man-in-the-middle-attack_Understanding_in_simple_words)



## Code Injection

Apps based on secure communication protocols (such as HTTPS) are not vulnerable to remote code injection attacks as an MitM attack is not possible unless vulnerabilities exist in an app’s SSL/TLS implementation, such as trusting all certificates, allowing all hostnames, trusting many CAs, and mixed-mode/no SSL. However, the use of HTTP and improper use of HTTPS are widespread problems in Android apps, resulting in remote code injection attacks still being a serious threat in today’s Android apps. The problem becomes complicated when apps maintain multiple connections and download multiple resources, because, all dynamic resource updates (DRU) have to be implemented securely. For example, apps generally apply HTTPS or integrity checking only to sensitive communications such as login, posting, purchasing, and self-updating activities and critical procedures. Remote code injection attacks can also be accomplished via other DRU resources such as images (.jpeg,  .gif, etc.) and configurations (.xml,  .json,  .txt,  etc.). App developers may not be cognizant of the security implications of all DRU resources downloaded and stored in the file system. For example, developers usually implement the theme updates for apps by simply downloading images via HTTP. [[9]](https://www.hindawi.com/journals/scn/2018/2489214/)

### Threats

- Dex code injection - android applications are packaged in APK (Android Package) files, which contain Dalvik Executable (DEX) files. Attackers may attempt to inject malicious DEX code into legitimate applications, exploiting vulnerabilities or using repackaging techniques. This can lead to the execution of unauthorized code within the context of the target application.
- Native code injection - android allows the use of native code through the Android Native Development Kit (NDK). Attackers may attempt to inject native code libraries (e.g., shared libraries in ELF format) into system applications, potentially compromising the integrity of the application and the device.
- JavaScript injection (WebView) - many Android applications use WebView components to display web content. Injection of malicious JavaScript code into WebView instances can lead to attacks such as Cross-Site Scripting (XSS) and may compromise the security of the application, exposing sensitive user data.
- Intent spoofing - android uses Intents for inter-component communication. Attackers may attempt to inject malicious Intents to impersonate legitimate system applications or components, leading to unauthorized access or execution of malicious actions.
- SQL injection - system applications often interact with databases to store and retrieve data. SQL injection attacks involve manipulating database queries by injecting malicious SQL code, potentially leading to unauthorized access or modification of data.
- Broadcast receiver attacks - system applications often use broadcast receivers to listen for system events. Attackers may attempt to inject malicious broadcasts to exploit vulnerabilities in the target application, leading to unauthorized actions or information disclosure. [[9]](https://www.hindawi.com/journals/scn/2018/2489214/)

### Attacks [TODO]

- SQL Injection: Exploiting poorly handled SQL queries.
- JavaScript Injection: Injecting malicious JavaScript code into webviews.

### Mitigations

- Filename sanitization - to defend against remote code injection attacks caused by file overwrite vulnerabilities, app developers should sanitize an input of filename. For example, before storing external resources coming from networks, it is important to filter out any characters that should not be included in a filename such as “./../”.
- Secure code execution - If app developers can employ secure APIs, which load and execute the downloaded executables in a secure manner, attackers would not be able to execute any arbitrary code within the context of an app even when successfully injecting their payload. During secure code execution, the involved API retrieves the certificate of the developer that signed and published the given code and verifies the downloaded code, which is cryptographically signed, using the retrieved certificate.
- Use of secure communication protocol - an ideal solution for preventing remote code injection attacks is to use a secure communication protocol (such as HTTPS) to download external resources. However, applying HTTPS for all communications is virtually impossible due to performance issues and operational costs. Because DRUs (such as downloading image files) occur very frequently in Android apps nowadays, applying HTTPS for all DRUs may affect performance.
- Least privilege principle - apply the principle of least privilege when assigning permissions to applications. Only grant the minimum set of permissions necessary for an application to function properly, reducing the potential impact of a compromise.
- Use WebView safely - if your application uses WebView, ensure that you implement proper input validation and output encoding to prevent JavaScript injection (XSS) attacks. Disable JavaScript if it is not required for your application.
- Secure broadcast receivers - be cautious when registering broadcast receivers in manifest files. Avoid using implicit intents and specify explicit targets to avoid unintended interactions. Additionally, validate input from broadcasts before processing. [[9]](https://www.hindawi.com/journals/scn/2018/2489214/)



## References

[1] [Comparative analysis of Android and iOS from security viewpoint](https://sci-hub.se/10.1016/j.cosrev.2021.100372?fbclid=IwAR3hN0s2rbXV_enFIgu_ykp1gyXQFtFdsNNZjMZ10MVzwVAG9F_wM8n9a94)

[2] [Android Malware Analysis and Conceptual Malware Mitigation Approaches](https://sci-hub.se/10.1109/ictc.2016.7763562)

[3] [Mobile Phishing Attack for Android Platform](https://sci-hub.se/10.1109/innovations.2014.6987555)

[4] [Mobile Phishing Attacks and Mitigation Techniques](https://www.scirp.org/html/5-7800290_57634.htm)

[5] [The Dangers of Rooting: Data Leakage Detection in Android Applications](https://www.hindawi.com/journals/misy/2018/6020461/)

[6] [Why Does Your Data Leak? Uncovering the Data Leakage in Cloud from Mobile Apps](https://sci-hub.se/10.1109/sp.2019.00009)

[7] [Android Forensics: Investigating Social Networking Cybercrimes against Man-in-the-Middle Attacks](https://sci-hub.se/10.1109/ccc.2016.15)

[8] [Man-in-the-middle-attack: Understanding in simple words](https://www.researchgate.net/publication/330249434_Man-in-the-middle-attack_Understanding_in_simple_words)

[9] [Large-Scale Analysis of Remote Code Injection Attacks in Android Apps](https://www.hindawi.com/journals/scn/2018/2489214/)
