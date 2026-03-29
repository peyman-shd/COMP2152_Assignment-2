"""
Author: Peyman Shahvand
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# TODO: Import the required modules (Step ii)
# socket, threading, sqlite3, os, platform, datetime
import socket
import threading
import sqlite3
import os
import platform
import datetime

# TODO: Print Python version and OS name (Step iii)
print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# TODO: Create the common_ports dictionary (Step iv)
# Stores common port numbers and their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

# TODO: Create the NetworkTool parent class (Step v)
# - Constructor: takes target, stores as private self.__target
# - @property getter for target
# - @target.setter with empty string validation
# - Destructor: prints "NetworkTool instance destroyed"
class NetworkTool:

    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter lets us control how target is used instead of accessing it directly.
    # For example, we can stop users from setting it to an empty value.
    # This makes the code safer and prevents mistakes.        
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

# TODO: Create the PortScanner child class that inherits from NetworkTool (Step vi)
# - Constructor: call super().__init__(target), initialize self.scan_results = [], self.lock = threading.Lock()
# - Destructor: print "PortScanner instance destroyed", call super().__del__()
# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, so it doesn’t need to rewrite things like target.
# The target variable is already defined in NetworkTool and PortScanner can use it directly.
# This reduces code duplication and keeps the code cleaner.
class PortScanner(NetworkTool):

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    # - scan_port(self, port):
    # - try-except with socket operations
    # - Create socket, set timeout, connect_ex
    # - Determine Open/Closed status
    # - Look up service name from common_ports (use "Unknown" if not found)
    # - Acquire lock, append (port, status, service_name) tuple, release lock
    # - Close socket in finally block
    # - Catch socket.error, print error message
    def scan_port(self, port):
        sock = None

        # Q4: What would happen without try-except here?
        # If we remove try-except, the program can crash when an error happens.
        # For example, if the host is not reachable, the scan will stop.
        # With try-except, the program handles the error and continues scanning.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            service_name = common_ports.get(port, "Unknown")
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            if sock:
                sock.close()


    # - get_open_ports(self):
    # - Use list comprehension to return only "Open" results
    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]


    # - scan_range(self, start_port, end_port):
    # - Create threads list
    # - Create Thread for each port targeting scan_port
    # - Start all threads (one loop)
    # - Join all threads (separate loop)
    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading helps us check multiple ports at the same time, so the scan runs faster.
    # If we scan ports one by one, each port waits for the previous one to finish, which is slow.
    # Scanning 1024 ports without threads would take a long time because of delays in each connection.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


# TODO: Create save_results(target, results) function (Step vii)
# - Connect to scan_history.db
# - CREATE TABLE IF NOT EXISTS scans (id, target, port, status, service, scan_date)
# - INSERT each result with datetime.datetime.now()
# - Commit, close
# - Wrap in try-except for sqlite3.Error
def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for port, status, service in results:
            cursor.execute("INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now())))
        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Database error: {e}")


# TODO: Create load_past_scans() function (Step viii)
# - Connect to scan_history.db
# - SELECT all from scans
# - Print each row in readable format
# - Handle missing table/db: print "No past scans found."
# - Close connection
def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    
    # TODO: Get user input with try-except (Step ix)
    # - Target IP (default "127.0.0.1" if empty)
    # - Start port (1-1024)
    # - End port (1-1024, >= start port)
    # - Catch ValueError: "Invalid input. Please enter a valid integer."
    # - Range check: "Port must be between 1 and 1024."
    try:
        target = input("Enter target IP: ")
        if target == "":
            target = "127.0.0.1"

        start_port = int(input("Enter a starting port (1-1024): "))
        end_port = int(input("Enter an ending port (1-1024): "))
        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
    except ValueError:
        print("Invalid input. Please enter a valid integer")

    # TODO: After valid input (Step x)
    # - Create PortScanner object
    # - Print "Scanning {target} from port {start} to {end}..."
    # - Call scan_range()
    # - Call get_open_ports() and print results
    # - Print total open ports found
    # - Call save_results()
    # - Ask "Would you like to see past scan history? (yes/no): "
    # - If "yes", call load_past_scans()
    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)
    open_ports = scanner.get_open_ports()
    print(f"--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")
    print("------------")
    print(f"Total open ports found: {len(open_ports)}")
    save_results(target, scanner.scan_results)
    choice = input("Would you like to see past scan history? (yes/no): ")
    if choice.lower() == "yes":
        load_past_scans()
    
# Q5: New Feature Proposal
# I would add a feature to show only ports with known services.
# This can use a list comprehension to remove ports with "Unknown".
# It makes the results easier to read.
# Diagram: See diagram_101495398.png in the repository root
