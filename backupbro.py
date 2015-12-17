import datetime
import hashlib
import json
import os
import sys
import urllib
import urllib2
import base64
from ConfigParser import SafeConfigParser
from os.path import *
import logging
import subprocess
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

#Setup

parser = SafeConfigParser()
parser.read('backupbro.cfg')


# Keep a running log of messages for this session.
runlog = ""
logfile=expanduser(parser.get( 'backupbro', 'logfile'))
logging.basicConfig(filename=logfile,level=logging.DEBUG)

#Getting info from cfg file.


account_id=parser.get( 'backupbro','account_id' )
account_key=parser.get( 'backupbro','account_key' )



# Functions

def listdirs(folder):
    return [d for d in os.listdir(folder) if os.path.isdir(os.path.join(folder, d))]
def listfiles(folder):
    return [d for d in os.listdir(folder) if os.path.isfile(os.path.join(folder, d))]

def send_email(text):
    #Email setup.
    global parser
    email_to=parser.get( 'backupbro','email_to' )
    email_from=parser.get( 'backupbro','email_from' )
    EMAIL_HOST = parser.get( 'backupbro','smtp_server' )
    EMAIL_HOST_USER = parser.get( 'backupbro','smtp_user' )
    EMAIL_HOST_PASSWORD = parser.get( 'backupbro','smtp_password' )
    EMAIL_PORT = parser.get( 'backupbro','smtp_port' )

    msg = MIMEText(text)
    msg['Subject'] = "Backup bro run report - " + str(datetime.datetime.now())
    msg['From'] = email_from
    msg['To'] = email_to


    debuglevel = 10
    s = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
    s.set_debuglevel(debuglevel)
    s.ehlo()
    s.starttls()
    s.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
    s.sendmail(email_from, email_to, msg.as_string())
    s.quit()

# list_buckets lists the buckets available on Backblaze B2.
def list_buckets ( account_id, account_authorization_token, api_url ):
    # print account_authorization_token
    request = urllib2.Request(
	'%s/b2api/v1/b2_list_buckets' % api_url,
	json.dumps({ 'accountId' : account_id }),
	headers = { 'Authorization': account_authorization_token }
	)
    response = urllib2.urlopen(request)
    response_data = json.loads(response.read())
    response.close()
    return response_data

# upload_bucket uploads files from the directory into a bucket of the same name.
def upload_file(account_id, account_authorization_token, api_url, bucket_id, directory):
    current_dir = bucketdir + "/" + directory
    file_list = listfiles(current_dir)
    for file in file_list:
        alert_msg("Uploading file: " + file)
        upload_info = get_upload_url(account_id, account_authorization_token, api_url, bucket_id)
        # print upload_info
        upload_url = upload_info['uploadUrl']
        upload_authorization_token = upload_info['authorizationToken']
        content_type = 'b2/x-auto'
        local_file=current_dir + "/" + file
        headers = {
        'Authorization' : upload_authorization_token,
        'X-Bz-File-Name' :  b2_url_encode(file),
        'Content-Type' : content_type,
        'X-Bz-Content-Sha1': hex_sha1_of_file(local_file)
        }
        #print headers
        response = post_file(upload_url, headers, local_file)
       # print "Response:"
       # print response
        server_sha1 = response['contentSha1']
        server_content_length = response['contentLength']

        alert_msg( "Successfully uploaded: " + file + " : " + server_sha1 + " length: " + str(server_content_length) + " bytes.")


def b2_url_encode(s):
    """URL-encodes a unicode string to be sent to B2 in an HTTP header.
    """
    return urllib.quote(s.encode('utf-8'))

def post_file(url, headers, file_path):
    """Posts the contents of the file to the URL.
    """
    with open(file_path, 'rb') as data_file:
        if 'Content-Length' not in headers:
            headers['Content-Length'] = str(os.path.getsize(file_path))

        request = urllib2.Request(url, data_file, headers)
        try:
            response = urllib2.urlopen(request)
            response_data = json.loads(response.read())
            response.close()
            return response_data
        except:
            fail_exit("Error with upload.", file_path)

def hex_sha1_of_file(path):
    with open(path, 'rb') as f:
        block_size = 1024 * 1024
        digest = hashlib.sha1()
        while True:
            data = f.read(block_size)
            if len(data) == 0:
                break
            digest.update(data)
        return digest.hexdigest()


#create_bucket creates a bucket on the b2 service. Returns a bucketid.
def create_bucket ( account_id, account_authorization_token, api_url, bucket_name ):
    alert_msg( "Creating bucket: " + bucket_name)
    bucketType="allPrivate"
    url = api_url + '/b2api/v1/b2_create_bucket'
    params = {
    'accountId': account_id,
    'bucketName': bucket_name,
    'bucketType': bucketType
    }
    headers = {
    'Authorization': account_authorization_token
    }
    request = urllib2.Request(url, json.dumps(params), headers)
    try:
        response = urllib2.urlopen(request)
        response_data = json.loads(response.read())
        response.close()
        return response_data['bucketId']
    except Exception:
        fail_exit("Error creating bucket: ",directory)

# Get bucket url for upload.
def get_upload_url(account_id, account_authorization_token, api_url, bucket_id):
    # print "Get upload URL: " + bucket_id
    request = urllib2.Request(
        '%s/b2api/v1/b2_get_upload_url' % api_url,
        json.dumps({ 'bucketId' : bucket_id }),
        headers = { 'Authorization': account_authorization_token }
        )
    response = urllib2.urlopen(request)
    response_data = json.loads(response.read())
    response.close()
    return response_data



#Error handling
def fail_exit(message,data):
    alert_msg(message + " : " + data)
    alert_msg("Fatal error, exiting.")
    sys.exit(1)

def alert_msg(message_data):
    timestamp = str(datetime.datetime.now())
    log_msg = timestamp + ":" + message_data
    global runlog
    runlog+=log_msg + "\r\n"
    logging.info(log_msg)

def send_log():
    alert_msg("Sending log via email.")
    global runlog
    send_email(runlog)


# START

alert_msg("BackupBro Starting...")

# Get a list of 'buckets' from the bucketdir.

home = expanduser("~")
bucketdir= home + '/buckets'
bucketlist = listdirs(bucketdir)




#Authorize account and get a key.

basic_auth_string = 'Basic' + base64.b64encode(account_id + ":" + account_key)

headers = { 'Authorization': basic_auth_string }
request = urllib2.Request(
    'https://api.backblaze.com/b2api/v1/b2_authorize_account',
    headers = headers
    )
response = urllib2.urlopen(request)
response_data = json.loads(response.read())
response.close()

account_authorization_token = response_data['authorizationToken']
api_url = response_data['apiUrl']
download_url=response_data['downloadUrl']


# Get a list of buckets on the server.
server_buckets = list_buckets( account_id, account_authorization_token, api_url )
server_buckets = server_buckets['buckets']

# Loop through buckets and make sure they exist on b2.

for directory in bucketlist:
    match = 0
    alert_msg("Directory: " + directory)
    for bucket in server_buckets:
        if directory == bucket['bucketName']:
            bucket_id = bucket['bucketId']
            upload_file(account_id, account_authorization_token, api_url, bucket_id, directory)
            match = 1
    if match == 0:
        bucket_id = create_bucket(account_id, account_authorization_token, api_url, directory)
        if bucket_id is None:
            fail_exit("Error creating bucket",directory)
        upload_file(account_id, account_authorization_token, api_url, bucket_id, directory)

send_log()
alert_msg("BackupBro Stopped...")



