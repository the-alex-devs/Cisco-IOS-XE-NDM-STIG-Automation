import paramiko
import getpass
#from Cisco_NDM_V2R2_STIGenator.py import secret

host = input("Enter target hostname or IP address: ")
user = input("Username: ")
print("Enter password. Note: cursor will not move during typing.")
secret = getpass.getpass()
port = 22

print("Gathering necessary configs, please wait...")

print("Gathering running config...")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) #auto adds new host keys
ssh.connect(hostname=host, username=user, password=secret, port=port)

stdin, stdout, stderr = ssh.exec_command("show run")
config_output = stdout.readlines()
output = [line.rstrip() for line in config_output]

file = open("show_run.txt", "w")
file.write("\n".join(output))
file.close()

print("Running config successfully gathered.")
##############################
print("Gathering SNMP user config...")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) #auto adds new host keys
ssh.connect(hostname=host, username=user, password=secret, port=port)

stdin, stdout, stderr = ssh.exec_command("show snmp user")
config_output = stdout.readlines()
output = [line.rstrip() for line in config_output]

file = open("show_snmp_user.txt", "w")
file.write("\n".join(output))
file.close()

print("SNMP user information successfully gathered.")
##############################
print("Gathering version information...")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) #auto adds new host keys
ssh.connect(hostname=host, username=user, password=secret, port=port)

stdin, stdout, stderr = ssh.exec_command("show version")
config_output = stdout.readlines()
output = [line.rstrip() for line in config_output]

file = open("show_version.txt", "w")
file.write("\n".join(output))
file.close()

print("Version information successfully gathered.")
##############################
print("Gathering logging config...")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) #auto adds new host keys
ssh.connect(hostname=host, username=user, password=secret, port=port)

stdin, stdout, stderr = ssh.exec_command("show logging")
config_output = stdout.readlines()
output = [line.rstrip() for line in config_output]

file = open("show_logging.txt", "w")
file.write("\n".join(output))
file.close()

print("Logging config successfully gathered.")
##############################
