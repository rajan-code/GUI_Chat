from __future__ import annotations

import random
import socket
import threading
import smtplib
import string
from typing import *
import os

# HOST = '139.177.194.104'  # ssh ip address
# HOST = '192.168.0.24'
HOST = ''
PORT = 5555

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()


class System:

    servers: List[Server]

    def __init__(self):
        self.servers = []

    def receive_all(self):
        for server in self.servers:
            server.receive()


class Server:
    commands = ['GET_USERS', 'EMAIL', 'GET_EMAILS', 'GET_PASSWORDS', 'NEW USER', 'NICK']

    def __init__(self):
        self.clients = []
        self.names = []  # List[bytes]
        self.online_users = set()  # Set[str]
        self.prev_msg_sender = None  # whoever sent the most recent message
        self.groups_ids = set()

    def broadcast(self, message: bytes):
        for client in self.clients:
            client.send(message)

    def receive_new_group(self, client):
        while True:
            message = client.recv(1024)  # get message
            decoded = message.decode()
            if decoded[:5] == 'GROUP':
                decoded = decoded[5:]
                print(f"New group created! Group id: {decoded}", flush=True)
                self.groups_ids.add(int(
                    decoded[5:]))  # error check if group_id already used
                break

    def handle(self, client: socket.socket):  # handle client
        while True:
            try:
                message = client.recv(1024)  # get message
                # print('Server received 1:', message, flush=True)
                decoded = message.decode('utf-8')
                if message == '':
                    continue
                elif decoded[:4] == 'NICK' and '\n' not in decoded:
                    decoded = decoded[4:]
                    print(f"{decoded} has connected!")
                    self.online_users.add(decoded)
                    self.broadcast(f"{decoded} has joined the group chat!\n".encode('utf-8'))  # prints message in app
                    client.send("Connected to the server\n".encode('utf-8'))
                    continue
                elif decoded[:9] == 'GET_USERS' and '\n' not in decoded:
                    users = get_usernames('users_info.txt')
                    str_users = str(users)
                    client.send(str_users.encode('utf-8'))
                    # print('Server sent:', str_users, flush=True)
                    continue
                elif decoded[:13] == 'GET_PASSWORDS' and '\n' not in decoded:
                    passwords = get_passwords('users_info.txt')
                    str_passwords = str(passwords)
                    client.send(str_passwords.encode('utf-8'))
                    # print('Server sent:', str_passwords, flush=True)
                    continue
                elif decoded[:10] == 'GET_EMAILS' and '\n' not in decoded:
                    emails = get_emails('users_info.txt')
                    str_emails = str(emails)
                    client.send(str_emails.encode('utf-8'))
                    # print('Server sent:', str_emails, flush=True)
                    continue

                elif decoded[:8] == 'NEW USER' and '\n' not in decoded:
                    line = decoded[9:]  # username,email,encoded password
                    with open('users_info.txt', 'a+') as file:
                        # Adds user info to txt file
                        file.write(f"\n{line}")
                    continue
                elif decoded[:5] == 'EMAIL' and '\n' not in decoded:
                    email = decoded[6:]
                    code = send_email(email)  # send email containing code
                    code = 'CODE ' + code
                    client.send(code.encode('utf-8'))  # must send twice
                    print('Server sent: ', code, flush=True)
                    continue

                elif decoded[:5] == 'GROUP' and '\n' not in decoded:  # can remove
                    group_id = random.randint(10000, 99999)
                    while group_id in self.groups_ids:  # if this number is already being used
                        group_id = random.randint(10000, 99999)
                    self.groups_ids.add(group_id)
                    print(f"New group created: {group_id}", flush=True)
                    msg = 'GROUP' + str(group_id)
                    print('Server sending:', msg, flush=True)
                    client.send(msg.encode('utf-8'))
                    self.broadcast(message)
                    continue
                # print(f"{self.names[self.clients.index(client)]}: {message}")
                if self.prev_msg_sender != client:  # if a different person is messaging
                    message = ('\n').encode('utf-8') + message
                self.prev_msg_sender = client
                self.broadcast(message)
            except:
                index_ = self.clients.index(client)
                client.close()
                print('Closed client', flush=True)
                self.clients.pop(index_)  # Remove client
                name = self.names.pop(index_)
                print(f"{name.decode('utf-8')} has disconnected")
                self.broadcast(f"{name.decode('utf-8')} has disconnected\n".encode('utf-8'))
                break

    def receive(self):
        while True:
            client, address = server.accept()  # accept new client
            print(f"Connected with {str(address)}")
            # client.send("NICK".encode('utf-8'))
            nickname = client.recv(1024)  # bytes object
            # client.send("GROUP".encode('utf-8'))
            # group_id = client.recv(1024).decode('utf-8')  # bytes object

            if self.prev_msg_sender is None:  # if this is the first client
                self.prev_msg_sender = client
            self.names.append(nickname)
            self.clients.append(client)
            print('self.clients', self.clients)
            decoded = nickname.decode('utf-8')
            # print('Server received 2:', decoded, flush=True)

            if decoded[:13] == 'GET_PASSWORDS' and '\n' not in decoded:
                passwords = get_passwords('users_info.txt')
                str_passwords = str(passwords)
                client.send(str_passwords.encode('utf-8'))
                # print('Server sent:', str_passwords, flush=True)
                thread = threading.Thread(target=self.handle, args=(client,))
                thread.start()
            if decoded[:10] == 'GET_EMAILS' and '\n' not in decoded:
                emails = get_emails('users_info.txt')
                str_emails = str(emails)
                client.send(str_emails.encode('utf-8'))
              #  print('Server sent:', str_emails, flush=True)
                thread = threading.Thread(target=self.handle, args=(client,))
                thread.start()
            elif decoded[:9] == 'GET_USERS' and '\n' not in decoded:
                users = get_usernames('users_info.txt')
                str_users = str(users)
                client.send(str_users.encode('utf-8'))
               # print('Server sent:', str_users, flush=True)
                thread = threading.Thread(target=self.handle, args=(client,))
                thread.start()
            elif decoded[:4] == 'NICK' and '\n' not in decoded:
                decoded = decoded[4:]
                print(f"{decoded} has connected!")
                self.online_users.add(decoded)
                self.broadcast(f"{decoded} has joined the group chat!\n".encode('utf-8'))  # prints message in app
                client.send("Connected to the server\n".encode('utf-8'))

                thread = threading.Thread(target=self.handle, args=(client,))
                thread.start()
                # thread2 = threading.Thread(target=self.receive_new_group, args=(client,))
                # thread2.start()
            elif decoded[:5] == 'EMAIL' and '\n' not in decoded:
                email = decoded[6:]
                code = send_email(email)  # send email containing code
                code = 'CODE ' + code
                client.send(code.encode('utf-8'))  # must send twice
                print('Server sent 3: ', code, flush=True)
                thread = threading.Thread(target=self.handle, args=(client,))
                thread.start()


def send_email(email: str) -> str:
    """
    Send email to <email> and return the 6-char long code
    """
    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()

        smtp.login('noreplymessagingapp@gmail.com', os.environ.get('EMAIL_PASSWORD'))

        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        subject = 'Account Almost Created!'
        body = 'Please enter the following code in the app to validate your account: ' + code

        msg = f'Subject: {subject}\n\n{body}'
        smtp.sendmail('noreplymessagingapp@gmail.com', email, msg)
    return code


def get_usernames(filename: str) -> List[str]:
    ans = []
    with open(filename, 'r') as file:
        lines = file.readlines()
        for line in lines[1:]:
            if line != '':
                line = line.split(',')
                ans.append(line[0])
    return ans


def get_emails(filename: str) -> List[str]:
    ans = []
    with open(filename, 'r') as file:
        lines = file.readlines()
        for line in lines[1:]:
            # print(line)
            if line != '':
                line = line.split(',')
                ans.append(line[1])
    return ans


def get_passwords(filename: str) -> List[str]:
    ans = []
    with open(filename, 'r') as file:
        lines = file.readlines()
        for line in lines[1:]:
            # print(line)
            if line != '':
                line = line.split(',')
                ans.append(line[2].rstrip('\n'))
    return ans


def get_dict_user(filename: str) -> Dict[str, List[str]]:
    """
    Return Dict that maps username to [email, encoded password]
    """
    ans = dict()
    with open(filename, 'r') as file:
        lines = file.readlines()
        for line in lines[1:]:
            if line != '':
                line = line.split(',')
                ans[line[0]] = [line[1], line[2].rstrip('\n')]
    return ans


if __name__ == '__main__':
    print('Server started')
    s1 = Server()
    try:
        s1.receive()
    except ConnectionResetError:
        print('Client disconnected')
