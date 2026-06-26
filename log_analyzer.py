# regex
import re

# regex pattern to match IP addresses
pattern = r"\d+\.\d+\.\d+\.\d+"

def read_file(filename):
    with open(filename, "r") as file:
        logs = file.readlines()
    return logs

def main():
    ip_counts = {}

    logs = read_file("auth.log")

    # Each line in the log gets printed if it is a failed password
    for line in logs:
        if "Failed password" in line:
            # checks each line to match IP address regex pattern
            match = re.search(pattern, line)
            if match: 
                ip = match.group()
                if ip in ip_counts:
                    ip_counts[ip] += 1
                else:
                    ip_counts[ip] = 1
                # if there is a match, then print out the ip address
    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")


if __name__ == "__main__":
    main()