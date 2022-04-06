import argparse # Be able to do cmd/terminal arguments
import socket # Be able to send packets to scan ports
import sys # For exiting the program
import threading # Enable us to do threading in program

# Number of processes to be able to print (1)
lock = threading.Semaphore(value=1)
def main():
    
    # Argparse to use arguments in CMD/Terminal
    parser = argparse.ArgumentParser(description="Simple TCP Scanner")
    
    # Create Arguments
    parser.add_argument("-H", dest="tgtHost", help="IP address to scan",
        required=True)
    parser.add_argument("-p", dest="tgtPorts", required=True, nargs="+",
        type=int, help="Ports to scan (space to seperate)")
    
    # Get all the arguments
    args = parser.parse_args()
    
    tgtHost = args.tgtHost
    tgtPorts = args.tgtPorts
    
    # Call the port scan function
    portScaner(tgtHost, tgtPorts)
    
def portScaner(tgtHost, tgtPorts):
    # Try to get target info
    try:
        # Returns (name, aliaselist, IPlist)
        tgtInfo = socket.gethostbyaddr(tgtHost)
        # Get one IP address
        tgtIp = tgtInfo[2][0]
        # Get name
        tgtName = tgtInfo[0]
    # User gave unknow host
    except:
        print("Unknown Host '%s'" % tgtHost)
        # Exit because theres no way we can scan an unknown host
        sys.exit()
    
    print("== Scan Results for: %s ==\n" % (tgtIp))
    
    # Sockets will now time out after 1 second
    socket.setdefaulttimeout(1)
    
    # Iterate through list of ports given
    for port in tgtPorts:
        # Tell thread what it will do, then start it
        thread = threading.Thread(target=tcpScan, args=(tgtHost, port))
        thread.start()

def tcpScan(tgtHost, tgtPort):
    # Tell the lock we are going to use it
    lock.acquire()
    print("[*] Scanning Port: %s" % tgtPort)
    try:
        # Create socket(IPv4, TCP)
        tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpSocket.connect((tgtHost, tgtPort))
        # Send binary (Py3 is actually binary) (Py2 binary is alias of str)
        tcpSocket.send(b"You!\r\n")
        result = tcpSocket.recv(1024)
        
        print("[*] %d/tcp open" % tgtPort)
        # Decode result (which is in binary) to utf-8, only for Py3
        print("[*] " + result.decode(encoding="utf-8"))
    except:
        print("[*] %d/tcp closed\n" % tgtPort)
    finally:
        # Realeaees whatever we need
        lock.release()
        tcpSocket.close()

if __name__ == "__main__":
    main()
