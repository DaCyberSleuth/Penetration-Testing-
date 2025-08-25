# Penetration-Testing-

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

- Kali Linux Virtual Machine served as the attacking machine for conducting Penetration testing in a controlled environment
- Burp Suite for Intercepting and capturing HTTP requests.
- SQLmap for Automated SQL Injection exploitation.
- Web Browser for Manual XSS payload injection and validation.
- Rukovoditel (v3.2.1) – Target application hosted in a Kali linux VM.


## Penetration Testing Methodology

### 1. Testing for Stored Cross-Site Scripting (XSS)

The Rukovoditel web-app contains a Stored Cross-Site Scripting (XSS) vulnerability in the `module=entities` endpoint.

#### Steps:

- Navigated to the vulnerable endpoint in Rukovoditel:`http://localhost/rukovoditel/index.php?module=entities/`

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

A reflected Cross-Site Scripting (XSS) vulnerability was identified in the `id` parameter of the `module=entities/fields_form_internal&id=1&entities_id=1` endpoint. The application does not properly sanitize user-supplied input before immediately reflecting it within the application's response. This allows an attacker to craft a malicious URL which, when visited by a victim, executes arbitrary JavaScript code in the context of the victim's browser session.

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

