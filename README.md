# Active Directory Home Lab Simulation with PowerShell - NSUK.NG
This project delivers a structured set of PowerShell scripts and best‑practice guidance for building and managing an Active Directory (AD) home lab. Its purpose is to equip administrators with automation tools for essential directory operations including creating and organizing users, groups, and organizational units (OUs), assigning permissions, and enforcing security baselines. By integrating account lockout policies to defend against brute‑force attacks and password complexity rules to strengthen authentication, the lab serves as both a training environment and a reference model for secure AD management.
# Prerequisites
i. Windows Server 2016 or later

ii. Active Directory Domain Services (AD DS) installed

iii. PowerShell 5.1 or later

iv. Domain Admin privileges

v. Static IP and DNS configured

# Home Lab Architecture Overview

**Stage 1: Environment Setup**

**Objectives**

i. Install AD DS

ii. Promote server to Domain Controller

iii. Verify domain configuration
# Project Structure
ActiveDirectoryHome/

│── Scripts/

│   ├── SetupDomain.ps1       # Initializes AD DS and promotes domain controller

│   ├── CreateUsers.ps1       # Automates user creation

│   ├── CreateGroups.ps1      # Defines and manages groups

│   ├── SetupOU.ps1           # Builds organizational units

│   ├── LockoutPolicy.ps1     # Configures account lockout policy

│   ├── PasswordPolicy.ps1    # Enforces password complexity rules

│   ├── Audit.ps1             # Audits accounts and policies

│── README.md                 # Main documentation

