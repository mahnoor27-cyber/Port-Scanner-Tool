import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import subprocess
import threading
from queue import Queue

# Function to check if the host is up
def is_host_up(ip):
    try:
        output = subprocess.run(
            ["ping", "-n", "1", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return "Reply from" in output.stdout
    except Exception as e:
        return False

# Function to get the MAC address for a given IP
def get_mac_address(ip):
    try:
        output = subprocess.run(
            ["arp", "-a", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        lines = output.stdout.splitlines()
        for line in lines:
            if ip in line:
                parts = line.split()
                return parts[1] if len(parts) > 1 else "MAC Not Found"
        return "MAC Not Found"
    except Exception as e:
        return "Error Retrieving MAC"

# Function to scan a single port
def scan_port(ip, port, results_queue):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"
            results_queue.put((port, "Open", service))
        else:
            results_queue.put((port, "Blocked/Filtered", "Unknown"))
        sock.close()
    except Exception as e:
        results_queue.put((port, "Error", "Unknown"))

# Function to scan multiple ports
def scan_ports(ip, start_port, end_port, output_text):
    results_queue = Queue()
    threads = []
    output_text.insert(tk.END, f"Scanning host {ip} from port {start_port} to {end_port}...\n")
    
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port, results_queue))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Print results
    while not results_queue.empty():
        port, status, service = results_queue.get()
        output_text.insert(tk.END, f"Port {port}: {status} (Service: {service})\n")

# Function to start the scan
def start_scan():
    target_ip = ip_entry.get()
    start_port = start_port_entry.get()
    end_port = end_port_entry.get()

    output_text.delete(1.0, tk.END)

    # Input validation
    if not target_ip or not start_port or not end_port:
        messagebox.showerror("Error", "Please fill in all fields.")
        return

    try:
        start_port = int(start_port)
        end_port = int(end_port)
    except ValueError:
        messagebox.showerror("Error", "Port numbers must be integers.")
        return

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        messagebox.showerror("Error", "Enter a valid port range (1-65535).")
        return

    # Check if host is up
    if is_host_up(target_ip):
        output_text.insert(tk.END, f"Host {target_ip} is Up.\n")
        
        # Get and display the MAC address
        mac_address = get_mac_address(target_ip)
        output_text.insert(tk.END, f"MAC Address for {target_ip}: {mac_address}\n")
        
        scan_ports(target_ip, start_port, end_port, output_text)
    else:
        output_text.insert(tk.END, f"Host {target_ip} is Not Up.\n")

# Function to clear the output area
def clear_output():
    output_text.delete(1.0, tk.END)

# Function to exit the application
def exit_app():
    window.destroy()

# Create the GUI
window = tk.Tk()
window.title("Port Scanner")
window.geometry("600x450")
window.config(bg="#2d3e50")  # Set a dark blue-gray background

# Header
header_label = tk.Label(window, text="Port Scanner", font=("Arial", 20, "bold"), bg="#2d3e50", fg="white")
header_label.pack(pady=10)

# IP Address
ip_frame = tk.Frame(window, bg="#2d3e50")
ip_frame.pack(pady=5)
ip_label = tk.Label(ip_frame, text="Target IP:", bg="#2d3e50", fg="white")
ip_label.pack(side=tk.LEFT, padx=5)
ip_entry = tk.Entry(ip_frame, width=20)
ip_entry.pack(side=tk.LEFT, padx=5)

# Port Range
port_frame = tk.Frame(window, bg="#2d3e50")
port_frame.pack(pady=5)
start_port_label = tk.Label(port_frame, text="Start Port:", bg="#2d3e50", fg="white")
start_port_label.pack(side=tk.LEFT, padx=5)
start_port_entry = tk.Entry(port_frame, width=10)
start_port_entry.pack(side=tk.LEFT, padx=5)

end_port_label = tk.Label(port_frame, text="End Port:", bg="#2d3e50", fg="white")
end_port_label.pack(side=tk.LEFT, padx=5)
end_port_entry = tk.Entry(port_frame, width=10)
end_port_entry.pack(side=tk.LEFT, padx=5)

# Buttons
button_frame = tk.Frame(window, bg="#2d3e50")
button_frame.pack(pady=10)
scan_button = tk.Button(button_frame, text="Start Scan", command=start_scan, bg="green", fg="white", width=12)
scan_button.pack(side=tk.LEFT, padx=10)
clear_button = tk.Button(button_frame, text="Clear Output", command=clear_output, bg="blue", fg="white", width=12)
clear_button.pack(side=tk.LEFT, padx=10)
exit_button = tk.Button(button_frame, text="Exit", command=exit_app, bg="red", fg="white", width=12)
exit_button.pack(side=tk.LEFT, padx=10)

# Output Text Area
output_frame = tk.Frame(window, bg="#2d3e50")
output_frame.pack(pady=10)
output_text = scrolledtext.ScrolledText(output_frame, width=70, height=15, bg="#eef2f3", fg="black", wrap=tk.WORD)
output_text.pack()

window.mainloop()
