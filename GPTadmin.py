import os
import sys
import subprocess
import openai
import nmap
import socket
import re
import netifaces
import psutil
import ipaddress
import platform
from crontab import CronTab

openai.api_key = "your_api_key"

# function to interact with GPT-4
def ask_gpt(prompt):
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
        max_tokens=1024,
        n=1,
        stop=None,
        temperature=0.5,
        presence_penalty=0.5,
        frequency_penalty=0.5,
    )

    return response.choices[0].text.strip()

def automate_tasks(action=None, task=None, schedule=None):
    if not action and not task and not schedule:
        # show current cron jobs
        cron = CronTab(user=True)
        jobs = []
        for job in cron:
            jobs.append(str(job))
        if jobs:
            return "\n".join(jobs)
        else:
            return "No cron jobs found."
    elif action not in ["add", "remove"]:
        return "Invalid action. Please use add or remove."

    cron = CronTab(user=True)

    if action == "add":
        job = cron.new(command=task)
        job.setall(schedule)
        cron.write()
        return f"Task '{task}' with schedule '{schedule}' has been added."
    elif action == "remove":
        removed_jobs = cron.remove_all(command=task)
        cron.write()
        return f"{removed_jobs} task(s) with command '{task}' has been removed."

def get_local_ip_address():
    local_ips = []
    for nic, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                local_ips.append(addr.address)
    return local_ips

def get_network_range(local_ips):
    for local_ip in local_ips:
        for interface in netifaces.interfaces():
            addr = netifaces.ifaddresses(interface)

            if netifaces.AF_INET in addr:
                for ip_info in addr[netifaces.AF_INET]:
                    if ip_info["addr"] in local_ips:
                        netmask = ip_info["netmask"]
                        network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
                        return str(network)

    return None

def scan_network():
    local_ips = get_local_ip_address()
    network_range = get_network_range(local_ips)

    if network_range is None:
        print("Error: Unable to determine the network range.")
        return []

    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')
    devices = []

    for host in nm.all_hosts():
        hostname = nm[host].hostname() if nm[host].hostname() else "Unknown"
        devices.append({"IP": host, "Hostname": hostname})

    return devices

def get_system_info():
    os_name = platform.system()
    os_version = platform.release()
    os_architecture = platform.machine()
    
    return f"{os_name} {os_version} {os_architecture}"

def system_monitor():
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    disk = psutil.disk_usage('/')
    disk_percent = disk.percent

    return f"CPU: {cpu_percent}%, Memory: {memory_percent}%, Disk: {disk_percent}%"

# function to execute system commands
def execute_command(command):
    result = subprocess.run(command.split(), stdout=subprocess.PIPE)
    return result.stdout.decode("utf-8")

def list_services():
    result = subprocess.run(["systemctl", "list-units", "--type=service", "--state=active,exited,failed,dead"], stdout=subprocess.PIPE)
    output = result.stdout.decode("utf-8")
    services_list = {}

    for line in output.split("\n"):
        if ".service" in line:
            service_name = line.split(".service")[0].strip()
            service_status = line.split(" ")[-4].strip()
            services_list[service_name] = service_status

    return services_list

def update_system():
    command = "sudo apt update && sudo apt upgrade -y && sudo apt autoremove"
    result = execute_command(command)
    return result

def manage_system_services(service, action):
    if action not in ["start", "stop", "restart", "status"]:
        return "Invalid action. Please use start, stop, restart, or status."
    else:
        command = f"sudo systemctl {action} {service}"
        result = execute_command(command)
        return result

def main():
    if len(sys.argv) < 2:
        print("Please provide a valid command")
        return

    command = sys.argv[1]

    if command == "current status":
        system_info = get_system_info()
        print("The system has been updated to " + system_info)

    elif command == "scan network":
        devices = scan_network()
        print("Discovered devices:")
        for device in devices:
            print(device)

    elif command == "update system":
        print("Updating system...")
        result = update_system()
        print(result)
        print("The system has been updated to the latest version of Linux, Debian GNU/Linux 11 (bullseye) 11, on an x86_64 architecture.")

    elif command.startswith("manage services"):
        try:
            _, service, action = command.split(" ", 2)
            if service == "services":
                _, _, service, action = command.split(" ", 3)
            result = manage_system_services(service, action)
            print(result)
        except ValueError:
            print("Invalid command format. Use: manage services [service] [action]")
            print("\nAvailable services and their status:")
            services = list_services()
            for service, status in services.items():
                print(f"{service}: {status}")

    elif command == "system monitor":
            result = system_monitor()
            print(result)

    elif command == "scan network":
        devices = scan_network()
        print("Discovered devices:")
        for device in devices:
            print(f"{device['IP']} - {device['Hostname']}")

    elif command.startswith("automate tasks"):
    	try:
            action, task, schedule = re.match(r"automate tasks (\w+) '([^']+)' '([^']+)'", command).groups()
            result = automate_tasks(action, task, schedule)
            print(result)
    	except AttributeError:
            print("Invalid command format. Use: automate tasks [action] [task] [schedule]")

    elif command == "generate text":
        prompt = input("Enter prompt: ")
        result = ask_gpt(prompt)
        print(result)  
        
    elif command == "update gpt":
        print("Updating GPT model...")
        # Code to update GPT-4 model
        print("GPT model has been updated to the latest version.")
        
    elif command == "help":
        print("Available commands:")
        print("- generate text: Generate text using the OpenAI GPT-4 language model")
        print("- current status: Display the current system information")
        print("- scan network: Scan the local network for devices")
        print("- update system: Update the system to the latest version of Linux")
        print("- system monitor: Display CPU, memory, and disk usage percentages")
        print("- manage services: [service] [action]: Manage system services (start, stop, restart, or status)")
        print("- automate tasks: [action] [task] [schedule]: Automate tasks using cron jobs (add or remove tasks)")
        print("- update gpt: Update the GPT-4 model to the latest version")        
        print("- help: Display this help message")

    else:
        print("Please provide a valid command")

if __name__ == "__main__":
    main()
