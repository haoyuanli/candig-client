
import requests
import getpass
import time
import socket
import errno
import json

#from xvfbwrapper import Xvfb
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC



# Required non-python libraries/programs:
# - Firefox
# - xvfb

# Required Python libraries:
# - Selenium
# - xvfbwrapper


def google_login():

    #Returns an error if login failed
    #Returns google response otherwise

    
#    vdisplay = Xvfb()
#    vdisplay.start()
    
    username = raw_input("Email address: ")
    password = getpass.getpass("Password: ")
    payload = {'scope': 'openid profile email',
               'redirect_uri': 'http://127.0.0.1:1111',
               'response_type' : 'code',
               'client_id': ''
    }
    endpoints = requests.get('https://accounts.google.com/.well-known/openid-configuration').json()
        
    google_request = requests.get(endpoints['authorization_endpoint'], headers = payload, params = payload)

    driver = webdriver.Firefox()
    driver.get(google_request.url)
    
    elem = WebDriverWait(driver, 10).until(
        EC.visibility_of_element_located((By.ID, "Email")))
    elem.send_keys(username)
    elem.send_keys(Keys.RETURN)
    
    elem = WebDriverWait(driver, 10).until(
        EC.visibility_of_element_located((By.ID, "Passwd")))
    elem.send_keys(password)
    elem.send_keys(Keys.RETURN)


    time.sleep(10)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("localhost", 1111))
    s.listen(5)
    s.setblocking(0)
        
    elem = WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.ID, "submit_approve_access")))
    elem.click()

    while 1:
        try:
            (clientsocket, address) = s.accept()
            data = clientsocket.recv(4096)
            data = data.split("\n")[0].split()[1].split("&")[0].split("=")[1]
            payload2 = {'code': data, 
                        'client_id' : '',
                        'client_secret' : '',
                        'redirect_uri' : 'http://127.0.0.1:1111',
                        'grant_type' : 'authorization_code'
            }
                
            google_response = requests.post(endpoints['token_endpoint'], params = payload2)
            driver.close()
            s.close()
            vdisplay.stop()
            if 'error' in google_response:
                return None
            else:
                return google_response
            

        except IOError as e:
            if e.errno == errno.EWOULDBLOCK:
                pass

            
def keycloakLogin():
    # Returns the token if there is no error
    # Raises a ValueError otherwise

    payload = {'scope' : '',
               'redirect_uri' : '',
               'response_type' : 'code',
               'client_id' : ''}
    
    try:
        config = json.loads(open('oidcConfig.ini', 'r').read())
    except IOError:
        print "oidcConfig.ini file not found! Please create one!"
    except JSONDecodeError:
        print "Invalid JSON found in oidcConfig.ini. Please correct this and try again."
        

    payload['redirect_uri'] = config['redirect_uri']
    payload['client_id'] = config['client_id']
    payload['scope'] = config['scope']

    try:
        endpoints = requests.get(config['endpoint_uri']).json()
    except requests.exceptions.ConnectionError:
        print "Error in requesting endpoints. Please check the endpoint_uri in oidcConfig.ini"


    keycloakRequest = requests.get(endpoints['authorization_endpoint'], headers = payload, params = payload)

#    vdisplay = Xvfb()
#    vdisplay.start()

    driver = webdriver.Firefox()
    driver.get(keycloak_request.url)
    username = raw_input("Username: ")
    password = getpass.getpass("Password: ")
    try:
        elem = WebDriverWait(driver, 10).until(
            EC.visibility_of_element_located((By.ID, "username")))
        elem.send_keys(username)
    except TimeOutException:
        print "Could not send username due to timeout. Please check your configuration to ensure that the endpoint uri is valid."
    try:
        elem = WebDriverWait(driver, 10).until(
            EC.visibility_of_element_located((By.ID, "password")))
    except TimeOutException:
        print "Could not send username due to timeout. Please check your configuration to ensure that the endpoint uri is valid."
    elem.send_keys(password)
    elem.send_keys(Keys.RETURN)
    time.sleep(5)
    data = driver.current_url.split("=")[1].strip(" ").strip("\n")
    
    payload2 = {'code' : data,
                'grant_type' : 'authorization_code',
                'redirect_uri' : config['redirect_uri'],
                'client_id' : config['client_id'],
                'client_secret' : config['client_secret']
                }
    keycloakResponse = requests.post(endpoints['token_endpoint'], data = payload2).json()
                                         
    
    
    driver.close()
#    vdisplay.stop()

    if "error" in keycloakResponse:
        if "redirect_uri" in keycloakResponse['error_description']:
            print "Invalid redirect_uri. Please check oidcConfig.ini"
        elif "grant_type" in keycloakResponse['error_description']:
            print "Invalid grant type. Please try again."
        elif "not valid" in keycloakResponse['error_description']:
            print "Invalid password and username combination. Please try again."
        elif "client secret" in keycloakResponse['error_description']:
            print "Invalid client secret. Please check oidcConfig.ini"
        else:
            print "Unknown error. Please document all output and report it to us."

        raise ValueError
    else:
        print "Successfully authenticated"
        return keycloakResponse

    
        
def keycloakClientCredentialsLogin():
    try:
        config = json.loads(open('oidcConfig.ini', 'r').read())
    except IOError:
        print "oidcConfig.ini file not found! Please create one!"
    except JSONDecodeError:
        print "Invalid JSON found in oidcConfig.ini. Please correct this and try again."

    payload = {'grant_type' : 'password', 
               'client_id' : config['client_id'],
               'client_secret' : config['client_secret'],
               'scope' : 'openid',
               'username': '',
               'password': ''}

    endpoints = requests.get(config['endpoint_uri']).json()


    payload['username'] = raw_input("Username: ")
    payload['password'] = getpass.getpass("Password: ")

    keycloakResponse = requests.post(endpoints['token_endpoint'], data = payload).json()
    if "error" in keycloakResponse:
        if "redirect_uri" in keycloakResponse['error_description']:
            print "Invalid redirect_uri. Please check oidcConfig.ini"
        elif "grant_type" in keycloakResponse['error_description']:
            print "Invalid grant type. Please try again."
        elif "not valid" in keycloakResponse['error_description']:
            print "Invalid password and username combination. Please try again."
        elif "client secret" in keycloakResponse['error_description']:
            print "Invalid client secret. Please check oidcConfig.ini"
        else:
            print "Unknown error. Please document all output and report it to us."

        raise ValueError

    return keycloakResponse.json()






def isTokenValid(creds):
    try:
        config = json.loads(open('oidcConfig.ini', 'r').read())
    except IOError:
        print "oidcConfig.ini file not found! Please create one!"
    except JSONDecodeError:
        print "Invalid JSON found in oidcConfig.ini. Please correct this and try again."

    payload = {'access_token' : creds['access_token'],
               'refresh_token' : creds['refresh_token'],
               'client_id' : config['client_id'],
               'client_secret' : config['client_secret']}
    endpoints = requests.get(config['endpoint_uri']).json()    
    

    keycloakResponse = requests.post(endpoints['userinfo_endpoint'], data = payload)
    
    if "error" in keycloakResponse:
        return False
    return True



class InvalidTokenException(Exception):
    #    The token was invalid
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)
