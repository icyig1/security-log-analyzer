def read_file(filename):
    with open(filename, "r") as file:
        logs = file.readlines()
    return logs

def main():
    logs = read_log_file("auth.log")

    for line in logs:
        print(line.strip())

if __name__ == "__main__":
    main()