file = open("show_snmp_user.txt", "w")
file.write("SNMP config missing due to offline config file used. Please manually verify the compliance of this STIG.")
file.close()

##############################
file = open("show_version.txt", "w")
file.write("Version config missing due to offline config file used. Please manually verify the compliance of this STIG.")
file.close()


##############################
file = open("show_logging.txt", "w")
file.write("Logging config missing due to offline config file used. Please manually verify the compliance of this STIG.")
file.close()

##############################

print("placeholders created successfully.")
