import sys
import config
import json
from time import sleep

def on_message(self, message, changesInboxTimestamp, supersedesHistoryMessage, conversation):
	if message.author != config.username:
		message_dict = {
            'user': message.author,
            'message': message.body_xml,
            'room': conversation.identity,
        }
		sys.stdout.write(json.dumps(message_dict) + '\n')
		sys.stdout.flush()

def account_on_change(self, property_name):
    global loggedIn
    if property_name == 'status':
        if self.status == 'LOGGED_IN':
            loggedIn = True
            print('Login complete.')
        
def send_message(message):
    decoded = json.loads(line)
    conversation = MySkype.GetConversationByIdentity(decoded['room'])
    conversation.PostText(decoded['message'])

try:
    import lib.Skype as Skype
except ImportError:
    raise SystemExit('Program requires Skype and skypekit modules')

loggedIn = False

MySkype = Skype.GetSkype(config.keyFileName)
MySkype.Start()

Skype.Skype.OnMessage = on_message
Skype.Account.OnPropertyChange = account_on_change

print('Logging in with ' + config.username)
account = MySkype.GetAccount(config.username)
account.LoginWithPassword(config.password, False, False)

while loggedIn == False:
    sleep(1)
    
while True:
    line = sys.stdin.readline()
    try:
        send_message(line)
    except:
        continue
