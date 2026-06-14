# Pre-Security Capstone Lab: Login Attack Detection

## Project Overview
This project is a beginner cybersecurity capstone to reflect on what I have learned on TryHackMe's Pre-Security learning path. It uses Python and SQL to analyze a sample of simulated login events and detect repeated failed login attempts.

## Skills Showcased
- Cybersecurity Fundamentals
- Networking Basics
- IP Address Analysis
- Client-server Concepts
- Operating System Concepts
- Python Scripting
- SQL Databases
- Log Analysis
- CIA Triad Mapping
- Attack and Defense Thinking

## How It Works
1. A CSV file stores simulated login events.
2. Python reads the CSV file using UTF-8 encoding.
3. Events are inserted into a SQL database.
4. Failed logins are counted by IP address.
5. Each IP is then assigned a risk level.
6. The program recommends any necessary defensive actions.

## Risk Levels
| Failed Attempts | Risk |
|---:|---|
| 0-2 | Normal |
| 3-4 | Low |
| 5-9 | Medium |
| 10+ | High |

## Security Relevance
Repeated failed logins can indicate:
- Brute-force attacks
- Password guessing
- Credential stuffing
- Unauthorized access attempts

## CIA Triad Impact
This attack mainly affects confidentiality as reflected on the report because successful attacks on logins could allow unauthorized access to private accounts or sensitive data.

## Defensive Controls
Recommended defenses include:
- Multi-factor authentication (MFA)
- Account lockout policies
- Rate limiting
- Strong password rules
- Login monitoring
- Security Alerts

## What I Learned
This project helped me immensely by connecting cybersecurity fundamentals to a practical detection workflow built in Python. I learned how networks, operating systems, software, databases, and defensive security all connect in a basic security monitoring scenario.

## References
- TryHackMe. "Introduction to Cyber Security." TryHackMe, [https://tryhackme.com/](https://tryhackme.com/module/introduction-to-cyber-security)
- TryHackMe. "Network Fundamentals." TryHackMe, [https://tryhackme.com/](https://tryhackme.com/module/network-fundamentals)
- TryHackMe. "How The Web Works." TryHackMe, [https://tryhackme.com/](https://tryhackme.com/module/how-the-web-works)
- TryHackMe. "Computer Fundamentals." TryHackMe, [https://tryhackme.com/](https://tryhackme.com/module/computer-fundamentals)
- TryHackMe. "Operating Systems Basics." TryHackMe, [https://tryhackme.com/](https://tryhackme.com/module/operating-systems-basics)
- TryHackMe. "Software Basics." TryHackMe, [https://tryhackme.com/](https://tryhackme.com/module/software-basics)
- TryHackMe. "Attacks and Defenses." TryHackMe, [https://tryhackme.com/](https://tryhackme.com/module/attacks-and-defenses)


## Disclaimer
This project is for educational purposes only. It summarizes concepts learned through TryHackMe and does not include walkthrough answers, flags, or private room solutions.