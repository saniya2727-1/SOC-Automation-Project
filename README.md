# SOC Automation Project

## Objective
[Brief Objective - Remove this afterwards]

The SOC Automation Lab project aimed to build a simulated Security Operations Center (SOC) using open-source tools. The objective was to ingest Windows logs, detect malicious activity, and automate responses through a SOAR (Security Orchestration, Automation, and Response) platform. The project helped reinforce knowledge in log analysis, security automation, and case management workflows.

### Skills Learned
[Bullet Points - Remove this afterwards]

- Hands-on experience with SIEM and SOAR tools in a SOC workflow
- Implemented automated alert triage and enrichment using Shuffle SOAR
- Investigated malicious activity using Wazuh alerts
- Created and managed security cases using TheHive
- Improved ability to interpret Windows event logs and Sysmon data
- Developed troubleshooting and log correlation techniques across multiple platforms



### Tools Used
[Bullet Points - Remove this afterwards]

- Wazuh – for log analysis, alerting, and rule-based detections
- Sysmon – for detailed Windows event telemetry (processes, network, registry)
- Shuffle SOAR – for building automated workflows in response to alerts
- TheHive – for managing security incidents as cases
- Elasticsearch - for storing and visualizing logs and alerts
- Ubuntu – for deploying all SOC components in a lab environment



- 
## Steps
Ref 1: SOC Architecture Diagram
<img width="1010" height="933" alt="SOC Automation Project drawio" src="https://github.com/user-attachments/assets/b0d42558-528d-4f00-ad31-d2240846f501" />

📌 This diagram outlines the end-to-end flow of logs and alerts from the Windows endpoint to Wazuh and Elasticsearch, with automated responses triggered via Shuffle and case management handled in TheHive.

Ref 2: Shuffle SOAR Workflow

<img width="1000" height="687" alt="Screenshot 2025-07-28 at 5 58 48 PM" src="https://github.com/user-attachments/assets/b6eb44b1-69d8-4ebf-8107-6c182051be39" />

📌 This diagram shows the automated alert handling workflow built in Shuffle. It starts with a Wazuh webhook, extracts file hashes, queries VirusTotal, creates a case in TheHive, and sends an alert summary via email.

Ref 3: SHA256 Extraction Step

<img width="330" height="608" alt="Screenshot 2025-07-28 at 6 09 15 PM" src="https://github.com/user-attachments/assets/de3f048b-6a07-4098-a124-251bd1325265" />


📌 This step parses the SHA256 hash from the Wazuh alert payload to use in enrichment.

<img width="325" height="620" alt="Screenshot 2025-07-28 at 6 10 28 PM" src="https://github.com/user-attachments/assets/127f2057-1659-44be-8a55-bb9709524b7c" />


Ref 4: VirusTotal Query & Results

<img width="325" height="620" alt="Screenshot 2025-07-28 at 6 10 28 PM" src="https://github.com/user-attachments/assets/27c72570-269f-4463-a178-b1447c08e8ac" />

<img width="902" height="645" alt="Screenshot 2025-07-28 at 6 16 55 PM" src="https://github.com/user-attachments/assets/64ae4b6a-0a66-43bf-94cb-b855c1e90b70" />


📌 Automates IOC enrichment using VirusTotal API for file hash reputation.



Ref 5: Wazuh Alert Example
<img src="https://i.imgur.com/YOURIMAGEID.png" width="600"/>

📌 This alert in Wazuh shows detection of suspicious process creation, including a Mimikatz-related command, parsed from Sysmon logs.



Ref 6: TheHive Case View

<img width="1439" height="295" alt="Screenshot 2025-07-28 at 6 01 08 PM" src="https://github.com/user-attachments/assets/1df56e2d-20af-438a-8cb7-9855c617d876" />


📌 Cases in TheHive are populated with alert data and linked observables. Analysts can assign severity, track investigation, and launch Cortex analyzers.

Ref 7: 

<img width="1376" height="422" alt="Screenshot 2025-07-28 at 6 02 23 PM" src="https://github.com/user-attachments/assets/1380c6b6-e855-4bf0-8176-a84479781154" />


📌 Configured alert forwarding in Wazuh to automatically send high-priority security alerts via email for real-time notification and incident awareness.







