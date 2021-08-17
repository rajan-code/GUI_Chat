from __future__ import annotations

import ast
import socket
import threading
import time
import tkinter
import tkinter.scrolledtext
import hashlib
import re
from datetime import datetime
from tkinter import *
from typing import *

# HOST = '192.168.0.24'
HOST = '172.105.20.159'  # ssh ip address
PORT = 5555


class Client:
    """
    A client.
    """
    sock: socket
    nickname: str
    gui_done: bool
    running: bool

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((host, port))
        except ConnectionRefusedError:
            print('Server is currently down.')
            sys.exit(1)
        self.username = ''
        self.in_gc = False
        self.printed_not_valid_email = False
        self.written_incorrect_code = False
        self.group_id = 0  # the group this client is currently in
        self.first_screen_win = tkinter.Tk()
        self.reg_screen_win = tkinter.Tk()
        self.change_pswd_win = tkinter.Tk()
        self.login_screen_u_win = tkinter.Tk()
        self.login_screen_e_win = tkinter.Tk()
        self.win = tkinter.Tk()

        # msg = tkinter.Tk()
        # msg.withdraw()

        self.gui_done = False
        self.running = True

        first_screen = threading.Thread(target=self.first_screen)
        # main_menu = threading.Thread(target=self.main_menu)
        # gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive)

        first_screen.start()
        # main_menu.start()
        # gui_thread.start()
        receive_thread.start()

    def first_screen(self):  # Register/login/reset pw/delete account screen
        """
        The first window that appears when the program is run.
        It contains all the options (Register/login/change password/delete account).
        """
        self.first_screen_win = tkinter.Tk()
        self.first_screen_win.configure(bg="lightgray")

        register_btn = tkinter.Button(self.first_screen_win, text="Register",
                                      command=lambda: [
                                          self.first_screen_win.withdraw(),
                                          self.register_screen()])
        register_btn.config(font=("Arial", 12))
        register_btn.pack(padx=20, pady=5)

        login_btn_1 = tkinter.Button(self.first_screen_win,
                                     text="Login with username",
                                     command=lambda: [
                                         self.first_screen_win.withdraw(),
                                         self.login_screen_u()])
        login_btn_1.config(font=("Arial", 12))
        login_btn_1.pack(padx=20, pady=5)

        login_btn_2 = tkinter.Button(self.first_screen_win,
                                     text="Login with e-mail",
                                     command=lambda: [
                                         self.first_screen_win.withdraw(),
                                         self.login_screen_e()])
        login_btn_2.config(font=("Arial", 12))
        login_btn_2.pack(padx=20, pady=5)

        reset_pswd_btn = tkinter.Button(self.first_screen_win,
                                        text="Reset Password",
                                        command=lambda: [self.first_screen_win.withdraw(),
                                         self.change_password_screen()])
        reset_pswd_btn.config(font=("Arial", 12))
        reset_pswd_btn.pack(padx=20, pady=5)

        reset_pswd_btn = tkinter.Button(self.first_screen_win,
                                        text="Delete account",
                                        command=lambda: [])
        reset_pswd_btn.config(font=("Arial", 12))
        reset_pswd_btn.pack(padx=20, pady=5)

        self.first_screen_win.protocol("WM_DELETE_WINDOW", self.stop)
        self.first_screen_win.mainloop()

    def successful_registration(self, successful: bool, line) -> None:
        """
        :param successful: True iff the user entered the correct code
        :param line: <username>,<email>,<encoded password>
        :return: None
        """
        self.reg_screen_win.geometry("500x350")
        if successful:
            l3 = Label(self.reg_screen_win,
                       text="You have successfully created an account!\n")
            l3.pack()
            l4 = Label(self.reg_screen_win,
                       text="Logging in and entering main menu...")
            l4.pack()
            # time.sleep(1.5)

            # send msg to server
            self.sock.send(("NEW USER " + line).encode('utf-8'))
            # print('Client sent: ("NEW USER" ' + line, flush=True)

            comma_index = line.index(',')
            self.username = line[:comma_index]
            self.reg_screen_win.withdraw()
            self.main_menu()
        elif not self.written_incorrect_code:
            l3 = Label(self.reg_screen_win,
                       text="Code is incorrect. Please try again.")
            l3.pack()
            self.written_incorrect_code = True

    def make_user(self, username: str, email: str, password: str, text3) -> None:
        """
        Register the user into the system if the username, email, and password
        are all valid. Else, print which parameters are invalid (and why they)
        are invalid to the screen.
        """
        self.reg_screen_win.geometry("500x350")
        # print(username, email, password, flush=True)
        self.sock.send('GET_USERS'.encode('utf-8'))
        # print('Client sent: GET_USERS', flush=True)
        peek = self.sock.recv(1024, socket.MSG_PEEK).decode('utf-8')
        # print('peek', peek)
        if 'baldski' in peek:  # change
            users = self.sock.recv(1024).decode('utf-8')
            users = ast.literal_eval(users)  # "['a', 'b']" -> ['a', 'b']
            # print('Client received 1:', users, flush=True)
        else:  # List of users was not received from server
            print("There was an error between the server and client.")
            exit(0)

        self.sock.send('GET_EMAILS'.encode('utf-8'))
        # print('Client sent: GET_EMAILS', flush=True)
        emails = self.sock.recv(1024).decode('utf-8')
        # print(emails, flush=True)
        emails = ast.literal_eval(emails)
        # print('Client received 1:', emails, flush=True)
        errors = ""

        if username in users:
            errors += 'Username is not available.\n'
        if email in emails:
            errors += 'There is an account that uses this email.\n'
        if len(username) == 0:
            errors += 'Username cannot be empty.\n'
        if not username.isalnum():
            errors += 'Username must be only contain letters and numbers.\n'
        if not is_valid_email(email):
            errors += 'Email is invalid.\n'
            self.printed_not_valid_email = True
        if len(password) < 5:
            errors += 'Password must be at least five characters long.\n'
        if errors != '':
            text3['text'] = errors
            text3.pack(padx=20, pady=5)
            return None
        else:
            text3['text'] = ''

        # info is good so make the user
        name_label = tkinter.Label(self.reg_screen_win,
                                   text="A confirmation email with a code has been sent to " + email)
        name_label.config(font=("Arial", 12))
        name_label.pack(padx=20, pady=5)
        self.sock.send(('EMAIL ' + email).encode('utf-8'))
        # print('Client sent: EMAIL', email, flush=True)
        peek = self.sock.recv(1024, socket.MSG_PEEK).decode('utf-8')
        # print('peeking:', peek)
        if 'CODE ' in peek:
            code = self.sock.recv(1024).decode('utf-8')  # receiving the 6-char long code
            code = code[5:]
            # print('Client received 2: CODE', code)  # r = 'CODE A3E4VB' for example

        encoded_pswd = hashlib.sha256(password.encode('utf-8')).hexdigest()
        line = username + ',' + email + ',' + encoded_pswd

        l3 = Label(self.reg_screen_win, text="Enter the code: ")
        l3.pack()
        enter_code = Entry(self.reg_screen_win)
        enter_code.pack()
        enter_btn = tkinter.Button(self.reg_screen_win, text="Enter",
                                   command=lambda: [
                                       self.successful_registration(
                                           enter_code.get() == code, line)])
        enter_btn.config(font=("Arial", 12))
        enter_btn.pack(padx=20, pady=5)

        # self.reg_screen_win.mainloop()

    def change_password(self, user, email, curr_pswd, new_pswd, text3) -> None:
        """
        Change this users password iff the info provided is correct.
        """
        user_dict = get_dict_user('users_info.txt')  # user -> [email, encoded pswd]
        if user not in user_dict:
            text3['text'] = 'Username or email or password is incorrect.'
            text3.pack(padx=20, pady=5)
            return
        if user_dict[user][0] != email or user_dict[user][1] != hashlib.sha256(curr_pswd.encode('utf-8')).hexdigest():
            text3['text'] = 'Username or email or password is incorrect.'
            text3.pack(padx=20, pady=5)
            return
        if len(new_pswd) < 5:
            text3['text'] = 'New password must be at least 5 characters long.'
            text3.pack(padx=20, pady=5)
            return
        print('changing password')
        # TODO change password by updating users_info.txt
        # send msg to server

    def change_password_screen(self):
        """
        The screen for changing password.
        """
        self.change_pswd_win = tkinter.Tk()
        self.change_pswd_win.geometry("500x350")
        l3 = Label(self.change_pswd_win, text="Username: ")
        l3.pack()
        username = Entry(self.change_pswd_win, width='40')
        username.pack()
        l2 = Label(self.change_pswd_win, text="Email: ")
        l2.pack()
        email = Entry(self.change_pswd_win, width='40')
        email.pack()
        l4 = Label(self.change_pswd_win, text="Current password: ")
        l4.pack()
        password = Entry(self.change_pswd_win, show='*', width='40')
        password.pack()
        l5 = Label(self.change_pswd_win, text="New password: ")
        l5.pack()
        new_password = Entry(self.change_pswd_win, show='*', width='40')
        new_password.pack()

        text3 = tkinter.Label(self.change_pswd_win, fg='black', height=2)
        change_pswd_btn = tkinter.Button(self.change_pswd_win,
                                         text="Change password",
                                         command=lambda: [self.change_password(username.get(), email.get(),password.get(), new_password.get(),text3)])
        change_pswd_btn.config(font=("Arial", 10))
        change_pswd_btn.pack(padx=18, pady=5)

    def login_screen_e(self) -> None:
        """
        The login screen if the client is logging in with their email.
        """
        self.login_screen_e_win = tkinter.Tk()
        self.login_screen_e_win.geometry("500x350")
        l2 = Label(self.login_screen_e_win, text="Email: ")
        l2.pack()
        email = Entry(self.login_screen_e_win, width='40')
        email.pack()
        l3 = Label(self.login_screen_e_win, text="Password: ")
        l3.pack()
        password = Entry(self.login_screen_e_win, show='*', width='40')
        password.pack()

        text3 = tkinter.Label(self.login_screen_e_win, fg='black', height=2)
        login_btn = tkinter.Button(self.login_screen_e_win, text="Login",
                                   command=lambda: [self.login('', email.get(),
                                                               password.get(),
                                                               text3)])
        login_btn.config(font=("Arial", 10))
        login_btn.pack(padx=18, pady=5)

        self.login_screen_e_win.protocol("WM_DELETE_WINDOW", self.stop)
        self.login_screen_e_win.mainloop()

    def login_screen_u(self) -> None:
        """
        The login screen if the client is logging in with their username.
        """
        self.login_screen_u_win = tkinter.Tk()
        self.login_screen_u_win.geometry("500x350")
        l2 = Label(self.login_screen_u_win, text="Username: ")
        l2.pack()
        username = Entry(self.login_screen_u_win, width='40')
        username.pack()
        l3 = Label(self.login_screen_u_win, text="Password: ")
        l3.pack()
        password = Entry(self.login_screen_u_win, show='*', width='40')
        password.pack()

        text3 = tkinter.Label(self.login_screen_u_win, fg='black', height=2)
        login_btn = tkinter.Button(self.login_screen_u_win, text="Login",
                                   command=lambda: [
                                       self.login(username.get(), '',
                                                  password.get(), text3)])
        login_btn.config(font=("Arial", 10))
        login_btn.pack(padx=18, pady=5)

        # self.login_screen_u_win.protocol("WM_DELETE_WINDOW", self.stop)
        self.login_screen_u_win.mainloop()

    def login(self, user: str, email: str, password: str, text3: tkinter.Label):
        """
        Login this user if the information provided is correct. Else,
        print error to screen and return None.
        """
        if user == '':  # email was used to login
            # emails = get_emails('users_info.txt')
            self.sock.send('GET_EMAILS'.encode('utf-8'))
           # print('Client sent: GET_EMAILS', flush=True)
            emails = self.sock.recv(1024).decode('utf-8')
            emails = ast.literal_eval(emails)
          #  print('Client received 1:', emails, flush=True)
            if email not in emails:
                error = 'Email is not in system.'
                text3['text'] = error
                text3.pack(padx=20, pady=5)
                return
            index_ = emails.index(email)

            self.sock.send('GET_PASSWORDS'.encode('utf-8'))
            # print('Client sent: GET_PASSWORDS', flush=True)
            passwords = self.sock.recv(1024).decode('utf-8')
            passwords = ast.literal_eval(passwords)  # "['a', 'b']" -> ['a', 'b']
            # print('Client received 1:', passwords, flush=True)

            expected_password = passwords[index_]  # passwords are encoded
            if hashlib.sha256(password.encode(
                    'utf-8')).hexdigest() == expected_password:  # if password entered is correct
                print('logging in')
                text3['text'] = 'Logging in...'
                self.username = email # change later
                # make function that returns user given email
                time.sleep(1)
                self.login_screen_e_win.withdraw()
                self.main_menu()
            else:  # incorrect password
                error = 'Incorrect password.'
                text3['text'] = error
                text3.pack(padx=20, pady=5)
                return
        else:
            # users = get_usernames('users_info.txt')
            self.sock.send('GET_USERS'.encode('utf-8'))
            # print('Client sent: GET_USERS', flush=True)
            peek = self.sock.recv(1024, socket.MSG_PEEK).decode('utf-8')
            # print('peeked:', peek, flush=True)
            if 'baldski' in peek:  # if the list of users was actually received
                users = self.sock.recv(1024).decode('utf-8')
                users = ast.literal_eval(users)  # "['a', 'b']" -> ['a', 'b']
                # print('Client received 1:', users, flush=True)
                if user not in users:
                    error = 'User is not in system.'
                    text3['text'] = error
                    text3.pack(padx=20, pady=5)
                    return
                index_ = users.index(user)

                self.sock.send('GET_PASSWORDS'.encode('utf-8'))
                # print('Client sent: GET_PASSWORDS', flush=True)
                passwords = self.sock.recv(1024).decode('utf-8')
                passwords = ast.literal_eval(
                    passwords)  # "['a', 'b']" -> ['a', 'b']
               # print('Client received 1:', passwords, flush=True)

                expected_password = passwords[index_]  # passwords are encoded
                if hashlib.sha256(password.encode(
                        'utf-8')).hexdigest() == expected_password:  # password entered is correct
                    print('logging in')
                    self.username = user
                    text3['text'] = 'Logging in...'
                    text3.pack(padx=20, pady=5)
                    time.sleep(1)
                    self.login_screen_u_win.withdraw()
                    self.main_menu()
                else:  # incorrect password
                    error = 'Incorrect password.'
                    text3['text'] = error
                    text3.pack(padx=20, pady=5)
                    return
            else:
                print('Users were not received properly', flush=True)
                exit(-1)

    def register_screen(self):
        """
        The register screen. The user enters their username, email, and
        password.
        """
        self.reg_screen_win = tkinter.Tk()
        self.reg_screen_win.geometry("500x200")
        self.reg_screen_win.title('Register')
        l1 = Label(self.reg_screen_win, text="Username: ")
        l1.pack()
        username = Entry(self.reg_screen_win, width='40')
        username.pack()
        l2 = Label(self.reg_screen_win, text="Email: ")
        l2.pack()
        email = Entry(self.reg_screen_win, width='40')
        email.pack()
        l3 = Label(self.reg_screen_win, text="Password: ")
        l3.pack()
        password = Entry(self.reg_screen_win, show='*', width='40')
        password.pack()

        text3 = tkinter.Label(self.reg_screen_win, fg='black', height=4)
        register_btn_ = tkinter.Button(self.reg_screen_win, text="Register",
                                       command=lambda: [
                                           self.make_user(username.get(),
                                                          email.get(),
                                                          password.get(), text3)])
        register_btn_.config(font=("Arial", 10))
        register_btn_.pack(padx=18, pady=5)

        # email = email.get()
        # print(email, flush=True)

        text = tkinter.Text(self.reg_screen_win)
        text.insert('end', "An email has been sent to")

        self.reg_screen_win.protocol("WM_DELETE_WINDOW", self.stop)
        self.reg_screen_win.mainloop()

    def list_online_clients(self):  #TODO
        """
        List all clients that are currently online.
        """
        list_clients = tkinter.Tk()
        list_clients.configure(bg="lightgray")

    def start_gui_thread(self):
        """
        Start gui thread.
        """
        gui_thread = threading.Thread(target=self.gui_loop)
        gui_thread.start()

    def main_menu(self):
        """
        The main menu. The user can enter a group chat or exit the program.
        """
        # if not correct_code: return None
        self.win = tkinter.Tk()
        self.win.geometry("500x350")
        self.win.configure(bg="lightgray")

        name_label = tkinter.Label(self.win,
                                   text="Welcome to ______ " + self.username,
                                   bg="lightgray")
        name_label.config(font=("Arial bold", 12))
        name_label.pack(padx=20, pady=5)

        name_label = tkinter.Label(self.win, text="Direct Messages\n",
                                   bg="lightgray")
        name_label.config(font=("Arial", 12))
        name_label.pack(padx=20, pady=5)

        name_label = tkinter.Label(self.win, text="Group Chats",
                                   bg="lightgray")
        name_label.config(font=("Arial", 12))
        name_label.pack(padx=20, pady=5)

        create_group_button = tkinter.Button(self.win, text="Join group chat",
                                             command=lambda: [
                                                 self.win.destroy(),
                                                 self.gui_loop(),
                                                 self.start_gui_thread()])
        create_group_button.config(font=("Arial", 12))
        create_group_button.pack(padx=20, pady=5)

        # join_group_button = tkinter.Button(self.win, text="Join group chat",
        #                                  command=self.join_group)
        # join_group_button.config(font=("Arial", 12))
        # join_group_button.pack(padx=20, pady=5)

        self.win.protocol("WM_DELETE_WINDOW", self.stop)
        self.win.mainloop()

    """
    def join_group(self):
        # self.win = tkinter.Tk()
        name_label = tkinter.Label(self.win, text="Enter group code",
                                   bg="lightgray")
        name_label.config(font=("Arial", 12))
        name_label.pack(padx=20, pady=5)

        self.input_area = tkinter.Text(self.win, height=2)
        self.input_area.pack(padx=20, pady=5)

        enter_btn = tkinter.Button(self.win, text="Enter",
                                   command=lambda: [self.gui_loop(), self.increment_num_groups_open(),
                                       self.start_gui_thread()])
        enter_btn.config(font=("Arial", 12))
        enter_btn.pack(padx=20, pady=5)
        """
    def add_image(self):
        img = tkinter.PhotoImage(file="5Head.png")
        self.input_area.image_create(tkinter.END, image=img)

    def gui_loop(self) -> None:
        """
        Groupchat screen. Users can send/receive messages.
        """
        self.in_gc = True
        self.sock.send(('NICK' + self.username).encode('utf-8'))
        # print('sent NICK', flush=True)
        # this code was needed for having multiple groups:
        # group_id = random.randint(10000, 99999)
        # self.sock.send("GROUP".encode('utf-8'))
        # self.sock.recv(1024).decode('utf-8')  # receives 'GROUP'
        # print('Client received', group_id, flush=True)
        # group_id = int(group_id[5:])
        # message = self.sock.recv(1024).decode('utf-8')
        # if message == 'GROUP':
        # self.sock.send(str(group_id).encode('utf-8'))  # send group id through socket here
        self.win = tkinter.Tk()
        self.win.configure(bg="lightgray")

        menu_button = tkinter.Button(self.win, text="Back to Main Menu",
                                     command = lambda: [self.win.withdraw(), self.main_menu()])
        menu_button.config(font=("Arial", 12))
        menu_button.pack(padx=20, pady=5)

        self.name_label = tkinter.Label(self.win, text=self.username,
                                        bg="lightgray")
        self.name_label.config(font=("Arial", 12))
        self.name_label.pack(padx=20, pady=5)

        self.chat_label = tkinter.Label(self.win,
                                        text="Group code: " + str(self.group_id),
                                        bg="lightgray")
        self.chat_label.config(font=("Arial", 12))
        self.chat_label.pack(padx=20, pady=5)
        self.chat_label = tkinter.Label(self.win, text="Chat:", bg="lightgray")
        self.chat_label.config(font=("Arial", 12))
        self.chat_label.pack(padx=20, pady=5)

        self.text_area = tkinter.scrolledtext.ScrolledText(self.win)
        self.text_area.pack(padx=20, pady=5)
        self.text_area.config(state='disabled')  # user cannot edit chat history

        self.msg_label = tkinter.Label(self.win, text="Message:",
                                       bg="lightgray")
        self.msg_label.config(font=("Arial", 12))
        self.msg_label.pack(padx=20, pady=5)

        self.input_area = tkinter.Text(self.win, height=2)
        self.input_area.pack(padx=20, pady=5)

        msg_label = tkinter.Label(self.win, text="Press enter to send message",
                                  bg="lightgray")
        msg_label.config(font=("Arial", 12))
        msg_label.pack(padx=20, pady=5)

        img_btn = tkinter.Button(self.win, text='5Head', command=self.add_image)
        img_btn.config(font=("Arial", 12))
        img_btn.pack(padx=20, pady=5)

        x = self.input_area.get('1.0', 'end')

        # print(x, flush=True)
        # if self.input_area.get('1.0', 'end') != '\n':
        self.win.bind('<Return>', self.write)  # when user presses enter

        # print(self.input_area)
        # self.send_button = tkinter.Button(self.win, text="Send", command=self.write)
        # self.send_button.config(font=("Arial", 12))
        # self.send_button.pack(padx=20, pady=5)

        self.gui_done = True
        self.win.protocol("WM_DELETE_WINDOW", self.stop)
        self.win.mainloop()

    def write(self, event=None):  # when Enter is pressed this function is called
        """
        Send the message written by the user to the socket.
        Note: if <event> parameter is removed the code stops working. This is
        because of the way the write() function is called.
        """
        # print(self.input_area.get('1.0', 'end'))
        text = self.input_area.get('1.0', 'end')
        if text in ['\n\n', '\n', '']:  # if input area is empty
            dummy = 1
            self.input_area.delete('1.0',
                                   'end')  # reset text box where user types messages
            return None
        curr_time = datetime.now()
        if 0 <= curr_time.hour <= 12:  # morning
            if curr_time.hour == 0:
                curr_hour = curr_time.hour + 12
                curr_min = str(curr_time.minute).zfill(2)
                message = f"[{curr_hour}:{curr_min} AM] "
            else:
                message = '[' + curr_time.strftime("%H:%M AM") + '] '
        else:
            curr_hour = curr_time.hour - 12
            curr_min = str(curr_time.minute).zfill(2)
            message = f"[{curr_hour}:{curr_min} PM] "
            # message = '[' + curr_time.strftime("%H:%M PM") + '] '
        message += f"{self.username}: {text}"
        message = message.rstrip('\n')  # remove two \n's
        message += '\n'  # add one
        # self.sock.send(self.username.encode('utf-8'))  # send client (remove)
        self.sock.send(message.encode('utf-8'))  # send message to socket
        self.input_area.delete('1.0',
                               'end')  # reset text box where user types messages

    def receive(self):
        """
        Receive messages from the server and act accordingly.
        """
        while self.running:
            try:
                peek = self.sock.recv(1024, socket.MSG_PEEK).decode('utf-8')
                if '\n' in peek:
                    message = self.sock.recv(1024).decode('utf-8')
                    # print('Client received 3:', message)

               # print('here', message, flush=True)
               # if message == 'NICK':
               #     self.sock.send(('NICK' + self.username).encode('utf-8'))
               #     print('sent NICK', flush=True)
               # elif message[0:5] == 'GROUP' and '\n' not in message:
               #     group_id = int(message[5:])
               #     print(f'The group id is:{group_id}')
                #    self.group_id = group_id
                    #self.sock.send(('GROUP').encode('utf-8'))
                    msg_blue = False
                    if self.gui_done:
                       # print(message, flush=True)
                        if all([x in message for x in [']', ':', '\n']]):
                            # this message is an actual msg in the gc
                            s_index = message.index(']')
                            colon_index = message.find(':', message.find(':') + 1)  # get index of 2nd occurence of ':'
                            user_sending = message[s_index+2:colon_index]  # the user who sent this message
                           # print(user_sending, flush=True)
                            if user_sending == self.username:
                                self.text_area.config(state='normal')
                                self.text_area.tag_config('blue1', foreground='blue')
                                msg_blue = True
                            else:
                                self.text_area.config(state='normal')

                        if not msg_blue:
                            self.text_area.config(state='normal')
                            self.text_area.insert('end', message)
                        else:
                            self.text_area.insert('end', message, 'blue1')
                        # messages are printed to screen
                        # self.text_area.tag_config('blue', foreground='blue')
                        self.text_area.yview('end')  # scroll down
                        self.text_area.config(state='disabled')
            except ConnectionAbortedError:
                break
            except:
                self.sock.close()
                print('Closed socket 2', flush=True)
                break

    def stop(self):
        """
        Destroy window, close socket and exit gracefully.
        """
        self.running = False
        self.first_screen_win.destroy()
        self.sock.close()
        print('Closed socket 1', flush=True)
        exit(0)


def is_valid_email(email: str) -> bool:
    """
    Return True iff <email> is a valid email address.
    """
    regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'
    return bool(re.search(regex, email))


def get_dict_user(filename: str) -> Dict[str, List[str]]:
    """
    Return Dict that maps username to [email, encoded password]
    """
    ans = dict()
    with open(filename, 'r') as file:
        lines = file.readlines()
        for line in lines[1:]:
            line = line.split(',')
            ans[line[0]] = [line[1], line[2].rstrip('\n')]
    return ans


if __name__ == '__main__':
    c = Client(HOST, PORT)
