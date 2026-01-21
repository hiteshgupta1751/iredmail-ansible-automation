# Automated Email Infrastructure with iRedMail using Ansible

This repository demonstrates a production-grade email infrastructure built using iRedMail and fully automated with Ansible.

The project shows how a complete mail server setup can be deployed, customized, and managed programmatically — suitable for scalable email systems, warm-up servers, and relay-based infrastructures.

---

## Project Overview

This project automates the deployment of an iRedMail mail server on a fresh Linux server using Ansible.

It includes:
- Postfix (SMTP)
- Dovecot (IMAP/POP3)
- MySQL backend
- Multi-domain support
- Bulk user creation
- Relay configuration
- Service customization
- Idempotent Ansible playbooks

---

## Architecture

Internet  
→ Sender Apps / Scripts  
→ iRedMail (Postfix + Dovecot)  
→ Relay / Smart Host (optional)  
→ Final Receiver (Gmail, Outlook, etc.)

---

## Repository Structure

iredmail/
├── install.yaml
├── domain.yaml
├── user.yaml
├── add-domain-user.yaml
├── relay.yaml
├── add_relay.yaml
├── virtual.yaml
├── ansible.cfg
├── inventory/
├── scripts/
├── data/
└── virtual/

---

## Features

- Fully automated iRedMail installation
- Multi-domain support
- Bulk mailbox creation
- Relay host configuration
- Service hardening
- Lightweight setup for sending servers
- Repeatable deployments using Ansible

---

## How to Use

1. Configure inventory in inventory/hosts  
2. Run installation:
   ansible-playbook install.yaml  
3. Add domain:
   ansible-playbook domain.yaml  
4. Add users:
   ansible-playbook user.yaml  
5. Configure relay:
   ansible-playbook relay.yaml  

---

## Requirements

- Ubuntu 20.04+
- Ansible 2.12+
- Root access on target server
- Public IP with rDNS

---

## 📈 Use Cases

- Email warm-up servers
- Transactional email infrastructure
- Marketing email infrastructure
- Multi-domain mail testing
- Dev/Test email environments
- Learning real-world mail systems

---

## 🔐 Security Notes

- No passwords are committed (use Ansible Vault in production)
- Designed for isolated or controlled environments
- Strongly recommended to configure:
  - SPF
  - DKIM
  - DMARC
  - rDNS
  - TLS certificates

---

## 🧠 Learning Outcomes

This project demonstrates:

- Real-world Ansible automation
- Email infrastructure design
- Postfix & Dovecot internals
- SQL-based mailbox management
- Deliverability-aware architecture
- Production automation mindset

---

## 📜 Disclaimer

This project is for educational and infrastructure demonstration purposes only.

Do **NOT** use this setup for spam, abuse, or policy violations.  
Always follow your provider’s acceptable use policies.

## 👤 Author

Hitesh Gupta  
Email Infrastructure Automation

