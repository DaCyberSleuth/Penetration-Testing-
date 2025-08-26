# Penetration-Testing

## Objective 

The objective of this project was to identify and exploit specific vulnerabilities within the Rukovoditel project management system (v3.2.1), hosted in a controlled virtual lab environment. 

This project aimed to:
-	Demonstrate practical exploitation of common web vulnerabilities.
- Document proof-of-concept (PoC) attacks.
-	Map findings to business risks and MITRE ATT&CK techniques.
-	Provide actionable remediation strategies to reduce risk exposure.


 ## Business Context

 Rukovoditel is a web-based project management and CRM application used by many organizations to handle sensitive project data, client details, and operational workflows. If exploited, vulnerabilities such as XSS or SQL Injection could lead to:
 
- Financial fraud through manipulated transactions or invoices.
- Intellectual property theft from exposed project data.
-	Service downtime resulting from database compromise.
-	Loss of client trust due to data breaches or account hijacking.

For example, an organization like **Acme Technologies Ltd**, managing multi-million-pound software development contracts, could suffer severe reputational and financial damage if these vulnerabilities were exploited.


## Skills Demonstrated

- Manual and automated testing for XSS and SQL Injection.
-	Using Burp Suite as an interception proxy.
-	Exploiting SQL Injection with SQLmap.
-	Documenting vulnerabilities with evidence.
-	Linking technical vulnerabilities to business risks.
-	Providing remediation aligned with industry best practices.


## Tools used 

- Kali Linux Virtual Machine served as the attacking machine for SQL injection testing in a controlled environment.
- Windows VM hosting the rukovoditel web app was used to carryout testing for XSS.
- Burp Suite for Intercepting and capturing HTTP requests.
- SQLmap for Automated SQL Injection exploitation.
- Web Browser for Manual XSS payload injection and validation.


## Penetration Testing Methodology

### 1. Testing for Stored Cross-Site Scripting (XSS)

The Rukovoditel web-app contains a Stored Cross-Site Scripting (XSS) vulnerability in the **`module=entities`** endpoint.

#### Steps:

- Navigated to the vulnerable endpoint in Rukovoditel:**`http://localhost/rukovoditel/index.php?module=entities/`**

- On the page, the **Add new Entity** button was clicked. A proof-of-concept XSS payload was injected into the **Name** input field. The payload used was a simple script to generate an alert:
**<script>alert("HACKED!!")</script>**

- After saving the entity, an alert box was immediately triggered, confirming the presence of a client-side vulnerability. This demonstration proved that the injected payload is stored by the application and executed in the browser of any user who subsequently views that page, resulting in the persistent appearance of the alert box.

<img width="1440" height="900" alt="Screenshot 2024-11-13 at 10 28 46 AM" src="https://github.com/user-attachments/assets/69b42826-d37d-4164-848d-cd259397c3c5" />

*Ref 1: stored xss vulnerable endpoint in rukovoditel*

<img width="1440" height="900" alt="Screenshot 2024-11-13 at 10 30 22 AM" src="https://github.com/user-attachments/assets/9901efee-6dec-40f1-a048-9307f22cde31" />

*Ref 2: xss test payload injected into **Name** input field*

 <img width="1440" height="900" alt="Screenshot 2024-11-13 at 10 30 35 AM" src="https://github.com/user-attachments/assets/23a12bc5-4e97-4142-b020-bc7e7b8d2cbe" />
 
*Ref 3: alert box triggered, confirming vulnerability*


### 2. Testing for Reflected Cross-Site Scripting (XSS)

A reflected Cross-Site Scripting (XSS) vulnerability was identified in the `id` parameter of the **`module=entities/fields_form_internal&id=1&entities_id=1`** endpoint. The application does not properly sanitize user-supplied input before immediately reflecting it within the application's response. This allows an attacker to craft a malicious URL which, when visited by a victim, executes arbitrary JavaScript code in the context of the victim's browser session.

#### Steps:

- A proof-of-concept payload was crafted to demonstrate the vulnerability. The payload used was a standard JavaScript alert script, designed to break out of an existing HTML attribute context:
**"><script>alert('HACKED!');</scRipt>**
  
*The closing tag was intentionally misspelled (**</scRipt>**) to test for and bypass potential naive input filters.*

- The crafted payload was then injected into the value of the **id** parameter within the URL of the identified vulnerable endpoint. The resulting malicious URL was constructed as follows:
**`http://localhost/rukovoditel/index.php?module=entities/fields_form_internal&id="><script>alert("HACKED!");</scRipt>&entities_id=1`**

- This malicious URL was then loaded into an authenticated browser session. Upon page load, a JavaScript alert box displaying the message **"HACKED!"** was immediately triggered. The successful execution of the arbitrary script confirmed the presence of the reflected Cross-Site Scripting vulnerability.


<img width="1440" height="900" alt="Screenshot 2024-11-20 at 11 59 19 AM" src="https://github.com/user-attachments/assets/b108f3f6-3271-44ff-9885-43ad260d2c81" />

*Ref 4: alert box triggered confirming vulnerability*


### 3. Testing for SQL Injection

The testing for SQL injection vulnerabilities was performed on a kali linux vm using a combination of industry-standard tools. Burp Suite was utilized to capture and manipulate web requests, while SQLMap was used to automate the process of detecting and exploiting injectable parameters.

#### Steps:

- The Burp Suite Community Edition software was downloaded from the official PortSwigger website: **`https:/ /portswigger .net/burp/releases/professional-community-2024-11-2?
requestededition=community&requestedplatform=`**

<img width="1440" height="900" alt="Screenshot 2025-01-17 at 10 06 33 AM" src="https://github.com/user-attachments/assets/0ef1ca45-f26b-4bcc-bfc8-ae5738b548f2" />

*Ref 5: burp suite download page on portswigger website*

- Following the download, the installation was initiated via the system terminal. The following commands were executed sequentially:
  
  **`cd Downloads`** (to navigate to the
  *Downloads* directory)

  **`ls`** (to list the contents of the
  *Downloads* directory and confirm the
  presence of the downloaded file)

  **`chmod +x burpsuite
  _community_linux_arm64_v2024_11_2.sh`**
  (to grant permission to install
  downloaded burp suite file)

    **`./burpsuite_community_linux_arm64_v2024_
  11_2.sh`** (to lunch the installation
  process)

- Following a successful installation, Burp Suite was launched from the system's **Applications** menu.
   
<img width="1440" height="900" alt="Screenshot 2025-01-17 at 10 46 30 AM" src="https://github.com/user-attachments/assets/382afb88-87f1-4510-bd3f-fa2d4a46ab43" />

*Ref 6: burp suite welcome page*

<img width="1440" height="900" alt="Screenshot 2025-01-17 at 10 47 12 AM" src="https://github.com/user-attachments/assets/700c1891-ff0f-4713-9938-16dac083c9ba" />

*Ref 7: burp suite Dashboard*

- To enable the interception of HTTP/S traffic, the local web browser was configured to route its communications through the Burp Suite proxy. This was accomplished by modifying the browser's network settings.

  The proxy was set to the following   parameters:
  **HTTP Proxy:** `127.0.0.1` (localhost)    **Port:** `8080`

  This configuration directed all browser
  traffic to the default listener port
  used by Burp Suite, allowing for the
  capture and analysis of outgoing
  requests and incoming responses.

<img width="1440" height="900" alt="Screenshot 2025-01-17 at 11 26 38 AM" src="https://github.com/user-attachments/assets/85335b24-b1f9-4a74-8b00-016f38ea5413" />
  
*Ref 8: browser configured to burp suite proxy*

- Navigated to the identified potentially vulnerable endpoint within the **Rukovoditel** web application
**`http://172.16.176.129/rukovoditel/index.php?module=logs/view&type=php`**

- The **intercept** feature within the Burp Suite proxy was enabled. This configuration allowed the tool to capture all HTTP requests routed from the browser, facilitating the analysis and manipulation of web traffic.

- Following the activation of the **intercept** feature within Burp Suite, a search query was then executed on the vulnerable endpoint of the Rukovoditel application using the search bar. The subsequent HTTP request, which contained the relevant query parameters, was successfully captured by the Burp Suite proxy

<img width="1440" height="900" alt="Screenshot 2025-01-17 at 12 56 05 PM" src="https://github.com/user-attachments/assets/fd5bf283-3324-4f11-bf33-f53c322ac96c" />

*Ref 9: **intercept** enabled in burp suite proxy*

<img width="1440" height="900" alt="Screenshot 2025-01-17 at 12 48 41 PM" src="https://github.com/user-attachments/assets/98e2edc7-383f-4a3c-aa17-8925804f49c8" />

*Ref 10: vulnerable endpoint in Rukovoditel web app showing the search bar*

- Following the execution of the search query, the resulting HTTP request was visible within the Burp Suite Proxy interface. The complete request, including headers, parameters and cookie sid, was then copied from the interface for further analysis.
<img width="1440" height="900" alt="Screenshot 2025-01-17 at 1 07 33 PM" src="https://github.com/user-attachments/assets/74c20512-23f0-4dcd-b03c-e3703a6573cf" />

*Ref 11: HTTP request visible on the burp suite proxy*

- A System terminal was opened, and a new file named **`testing.txt`** was created using the **`nano`** text editor with the following command:
**`nano testing.txt`**

  The complete HTTP request, previously
  copied from the Burp Suite proxy
  interface, was pasted into this newly
  created file. The file was then saved
  and closed to preserve the raw request
  data. This file served as the input
  payload for the subsequent automated SQL
  injection attack with SQLMap.

<img width="1440" height="900" alt="Screenshot 2025-01-17 at 1 33 06 PM" src="https://github.com/user-attachments/assets/92b7f18d-2002-4c50-b77a-fd2157e85283" />

*Ref 12: HTTP request saved in newly created **testing.txt** file*

- As **SQLmap** is a pre-installed tool on the Kali Linux distribution, no additional installation was required. The automated SQL injection testing phase was initiated directly from the system terminal.

  The following command was executed:
  **`sqlmap -r testing.txt --dbs**

  **Command Breakdown:**
  The **`-r`** flag instructed SQLmap to 
  read and analyze the HTTP request stored 
  in the **`testing.txt`** file.
  The **`--dbs`** flag directed the tool
  to, upon successful exploitation, 
  enumerate the available databases.

  This command configured SQLmap to test
  all parameters contained within the
  request body and headers of the captured
  HTTP request for SQL injection
  vulnerabilities. The primary objective
  of this initial command was to confirm
  the presence of a vulnerability and
  identify the databases accessible to the
  injected SQL query.

<img width="1440" height="900" alt="Screenshot 2025-01-17 at 1 41 29 PM" src="https://github.com/user-attachments/assets/a299b070-02c3-408c-982c-4be5a3cc410e" />

*Ref 13: SQLmap running and testing all parameters*

- The automated SQL injection test was successfully executed. SQLmap enumerated **seven (7) databases** from the target system, confirming that the identified SQL injection vulnerability was exploitable.

This successful database enumeration demonstrated a significant security flaw, indicating that an attacker could extract sensitive information from the backend database by exploiting the vulnerable parameter.

<img width="1440" height="900" alt="Screenshot 2025-01-17 at 1 42 34 PM" src="https://github.com/user-attachments/assets/52bd32a3-b8b8-4c81-ae12-51f7354f73c4" />

*Ref 14: Test succesfully enumerated 7 databases*


## Findings & Analysis


| #  | Vulnerability   | Description                                                                                   | Severity (CVSS) | MITRE ATT&CK Mapping |
|----|-----------------|-----------------------------------------------------------------------------------------------|-----------------|----------------------|
| 1  | Stored XSS      | Payload persisted in entity fields and executed every time the page was reloaded.             | High (8.0)      | T1059.007            |
| 2  | Reflected XSS   | Script injected via URL parameter was immediately reflected and executed in the browser.      | High (8.0)      | T1059.007            |
| 3  | SQL Injection   | Unsanitized inputs allowed database manipulation; SQLmap confirmed full DB enumeration.       | Critical (9.0)  | T1190                |


## Business Impact Analysis


| Vulnerability  | Potential Business Impact                                                      | Affected Functions             | Impact Category                     |
|----------------|--------------------------------------------------------------------------------|--------------------------------|-------------------------------------|
| Stored XSS     | Theft of cookies, user credentials, or session hijacking leading to account takeover. | User sessions, UI security      | Confidentiality, Integrity          |
| Reflected XSS  | Delivery of malicious payloads via crafted links; phishing or credential theft. | Customer-facing operations      | Confidentiality                     |
| SQL Injection  | Full compromise of application databases; unauthorized data access, deletion, or corruption. | Core data management, CRM       | Confidentiality, Integrity, Availability |


## Remediation


| Vulnerability  | Recommended Fix                                                                                                      |
|----------------|----------------------------------------------------------------------------------------------------------------------|
| Stored XSS     | Implement strict input validation and output encoding; sanitize user inputs before storage; enforce a Content Security Policy (CSP). |
| Reflected XSS  | Validate and sanitize all query string parameters; encode outputs; apply a strong Content Security Policy (CSP).     |
| SQL Injection  | Use parameterized queries (prepared statements), ensure the application uses least-privilege **database** accounts, and deploy a Web Application Firewall (WAF). |


## Connclusion

This assessment successfully demonstrated the exploitation of Stored XSS, Reflected XSS, and SQL Injection vulnerabilities in Rukovoditel v3.2.1.

These vulnerabilities, if left unaddressed, could lead to severe business impact, including data theft, service disruption, and reputational damage.

By implementing the recommended remediations — secure coding practices, regular patching, and stricter input handling — **Acme Technologies Ltd** can significantly reduce their attack surface and safeguard sensitive business operations.
