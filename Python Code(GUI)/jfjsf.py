import subprocess
import re

# List to store client ports
client_ports = []


# Function to run the proxy server and capture port numbers
def run_proxy():
    # Run the proxy.exe program using subprocess
    process = subprocess.Popen(['./proxy'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    while True:
        # Capture the output from the proxy server
        output = process.stdout.readline()

        if output == '' and process.poll() is not None:
            break  # Exit loop when the proxy.exe process finishes

        if output:
            # Look for the port number in the output (assuming the format is "Client connected from port: 56475")
            match = re.search(r"Client connected from port: (\d+)", output)

            if match:
                port = match.group(1)
                client_ports.append(port)
                print(f"Captured client port: {port}")

    # Return the list of captured ports
    return client_ports


# Run the proxy and capture client ports until the server stops
captured_ports = run_proxy()
print("All captured client ports:", captured_ports)
