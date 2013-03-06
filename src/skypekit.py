import sys
import json
import time
import os

def on_message(self, message, changesInboxTimestamp, supersedesHistoryMessage, conversation):
    if message.author != username and message.timestamp > launch_time:
        message_dict = {
            'user': message.author,
            'message': message.body_xml,
            'room': conversation.identity,
        }
        debug_log("Received %s", json.dumps(message_dict))
        write(message_dict)

def account_on_change(self, property_name):
    global loggedIn
    if property_name == 'status':
        if self.status == 'LOGGED_IN':
            loggedIn = True
            debug_log("Logged in")
        
def send_message(message):
    debug_log("Sending %s", message)
    decoded = json.loads(line)
    conversation = skype.GetConversationByIdentity(decoded['room'])
    conversation.PostText(decoded['message'])
    
def write(jsonDict):
    sys.stdout.write(json.dumps(jsonDict) + '\n')
    sys.stdout.flush()
    
def debug_log(log_message):
    if logging_enabled:
        log_dict = {
            '_debug_log_': log_message
        }
        write(log_dict)

try:
    import lib.Skype as Skype
except ImportError:
    raise SystemExit('Program requires Skype and skypekit modules')

username = os.environ['HUBOT_SKYPEKIT_USERNAME']
password = os.environ['HUBOT_SKYPEKIT_PASSWORD']
key_path = os.environ['HUBOT_SKYPEKIT_KEY_PATH']

logging_enabled = bool(os.environ.get('HUBOT_SKYPEKIT_LOG_ENABLED', 'false'))

loggedIn = False
launch_time = time.time()

debug_log("Starting up...")

skype = Skype.GetSkype(key_path)
skype.Start()

Skype.Skype.OnMessage = on_message
Skype.Account.OnPropertyChange = account_on_change

account = skype.GetAccount(username)
account.LoginWithPassword(password, False, False)

while loggedIn == False:
    time.sleep(1)
    
while True:
    line = sys.stdin.readline()
    try:
        send_message(line)
    except:
        continue
