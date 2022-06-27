# Cisco IOS XE NDM STIGenator Python STIG Script

This is a project coded in Python to automate performing the Cisco IOS XE NDM STIG checks and filling out the CKL with results of the STIG checks.

## Getting started

Python requirements:
- xml.etree
- getpass
- tkinter
- pathlib
- Paramiko

Other requirements:
- Credential that has permission to SSH to target device and perform various 'show' commands (only necessary for "online" mode).
- Port 22 connectivity to target device (only necessary for "online" mode).
- A "show run" config file for the target switch (only necessary for "offline" mode).

## Name
Cisco IOS XE NDM STIGenator

## Description
This is a project coded in Python to automate performing the Cisco IOS XE NDM STIG checks and filling out the CKL with results of the STIG checks. This project was designed with the goal to automate the STIG process of Cisco IOS XE switches. 

## Installation
Paramiko is the only non-default library used in this program. It will need to be installed in order for the current configuration to be gathered.

## Usage
You'll need both Python scripts in the same folder to get started. You'll run the Cisco_NDM_V2R2_STIGenator_v1.1.py script then you'll see several prompts for the target device, username, password, and target CKL file to be filled out. If the ssh connection is successful, it will immediately start performing the STIG checks. 

IMPORTANT: If you have any not applicable STIGs on the NDM checklist, be sure to mark them as Not Applicable BEFORE running the script! If the script sees that the current status is Not Applicable, it will skip that STIG check to not cause any unnecessary false positives.

If you plan on using the included blank CKL, don't forget to rename it or make copies before use. The STIGenator will overwrite the file and you'll need to get another blank CKL if you plan on using the STIGenator again.

Checking for STIG compliance is the only thing this script will do. It will NOT make any configuration changes on the target device.

When running the script , it should look like this before performing the STIG checks:
```
Would you like to use SSH to perform a live collection of switch configs to be STIG'd?  
(If 'no', then you'll be prompted to choose a .txt config file of the switch)
Please note that only most, but not all, STIG checks can be completed in 'offline mode'.
Please enter 'yes' or 'no':
```
By entering 'yes', the script will prompt you for target device IP/hostname then the credential to be used. If you enter 'no', it will prompt you to select a config file of the switch (a simple "show run" output works best) instead of using an SSH connection.

After you make your choice, it will begin parsing the configs for STIG compliance.

## Support
Feel free to create issues on this project!

## Roadmap
Things to be added in the future:
- More verbose Finding Details on STIG checks that require multiple lines of configuration to be compliant.
- Compatibility with CKLs exported from STIGMAN. - DONE W/ VERSION 1.1
- Easier to read logging in the Python console.
- Offline mode to select a configuration text file instead of using SSH connection to gather device config. - DONE W/ VERSION 1.1

## Contributing
I'm open to all contributions! The more eyes on this project, the better the automation tool can become.

## Authors and acknowledgment
Alex Dean - creator

## Project status
In progress and in testing phase currently. Base functionality of the program is working and I'd like to receive as much feedback as possible in order to improve it so it can be more useful to more people!

If I've forgotten anything to this readme, the scripts, or anything else, please let me know!
