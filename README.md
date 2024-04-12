# Nmap-s-future-rival
# XScanner
The user controls the program by providing command-line arguments when executing the program. In this case, the user needs to provide the host or IP address of the target system as a command-line argument. Here's how the user can control the program:

1. **Compile the Program:** First, the user compiles the program into an executable. For example, if the program is saved as `network_tool.cpp`, the user can compile it using a C++ compiler such as g++:
   ```
   g++ network_tool.cpp -o network_tool -lssl -lcrypto
   ```

2. **Execute the Program:** After compilation, the user can execute the program by providing the host or IP address of the target system as a command-line argument. For example:
   ```
   ./network_tool example.com
   ```

   Replace `example.com` with the actual host or IP address the user wants to scan.

3. **Program Output:** The program will then perform the following actions based on the user's input:
   - Ping the specified host to check if it's reachable.
   - Scan common ports (HTTP, HTTPS, SSH, FTP, Telnet) on the target system to determine if they are open.
   - Attempt to detect the versions of services running on open ports (HTTP, HTTPS, SSH, FTP, Telnet).

4. **Display Results:** The program will display the results of the ping, port scanning, and version detection operations on the command line.

By providing different host addresses as command-line arguments, the user can control which systems the program interacts with and retrieves information from.
REMEMBER GUYS THIS IS STILL IN DEVELOPMENT.DONT FORGET TO CONTRIBUTE TO NMAP'S FUTURE RIVAL.ALSO CHECK OUT QUANTUM WEB AND MATHOS AND CONTRIBUTE TO THEM TOO.
