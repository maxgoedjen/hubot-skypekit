import sys
import json
import time
import os
import HTMLParser
import re

def on_message(self, message, changesInboxTimestamp, supersedesHistoryMessage, conversation):
    if message.author != username and message.timestamp > launch_time:
        message_dict = {
            'user': message.author,
            'message': html_parser.unescape(message.body_xml),
            'room': conversation.identity,
        }
        debug_log("Received message", message_dict)
        write(message_dict)

def account_on_change(self, property_name):
    global loggedIn
    if property_name == 'status':
        if self.status == 'LOGGED_IN':
            loggedIn = True
            debug_log("Logged in")

def send_message(message):
    decoded = json.loads(line)
    debug_log("Sending message", decoded)
    if decoded['message'].startswith('/'):
        decoded['message'] = ' ' + decoded['message']
    conversation = skype.GetConversationByIdentity(decoded['room'])
    conversation.PostText(decoded['message'], is_xml=is_snippet_xml(decoded['message']))

def write(jsonDict):
    sys.stdout.write(json.dumps(jsonDict) + '\n')
    sys.stdout.flush()

def debug_log(log_message, log_data=None):
    if logging_enabled:
        log_dict = {
            '_debug_log_': log_message
        }
        if log_data:
            log_dict['_debug_data_'] = log_data
        write(log_dict)

def is_snippet_xml(snippet):

    if not '<' in snippet and not '>' in snippet:
        return False

    OPEN = re.compile('<([^/>]+)>')
    CLOSE = re.compile('</([^>]+)>')

    counts = {}

    open_tags = OPEN.findall(snippet)
    closed_tags = CLOSE.findall(snippet)

    for tag in open_tags:
        counts[tag] = counts.get(tag, 0) + 1

    for tag in closed_tags:
        counts[tag] = counts.get(tag, 0) - 1

    print counts
    for tag in counts:
        if counts[tag] != 0:
            debug_log("Unclosed tags")
            return False

    debug_log("Valid")
    return True

try:
    import lib.Skype as Skype
except ImportError:
    raise SystemExit('Program requires Skype and skypekit modules')

username = os.environ['HUBOT_SKYPEKIT_USERNAME']
password = os.environ['HUBOT_SKYPEKIT_PASSWORD']
key_path = os.environ['HUBOT_SKYPEKIT_KEY_PATH']

logging_enabled = os.environ.get('HUBOT_SKYPEKIT_LOG_ENABLED', '0') != '0'

loggedIn = False
launch_time = time.time()

debug_log("Starting up...")

skype = Skype.GetSkype(key_path)
skype.Start()


Skype.Skype.OnMessage = on_message
Skype.Account.OnPropertyChange = account_on_change

account = skype.GetAccount(username)
account.LoginWithPassword(password, False, False)

html_parser = HTMLParser.HTMLParser()

while loggedIn == False:
    time.sleep(1)

while True:
    line = sys.stdin.readline()
    try:
        send_message(line)
    except:
        continue
