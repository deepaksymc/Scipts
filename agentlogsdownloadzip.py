import requests
import json
import time
import sys
import re
import os

# Script to download and save agent logs using Public APIs.
# Customer has to pass Customer ID, Domain ID, Client ID and Client Secret Key as arguments. The keys are available in CWP portal's Settings->API Key tab.
# Instance id of the VM which can be obtained from Instance Details page
#  Usage: python downloadagentlogs.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <Instance ID>
clientsecret = 'xxxx'
clientID = 'xxx'
customerID = 'xxxx'
domainID = 'xxxxx'
instanceid = 'xxxx'


def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor

# Function to call CWP REST API and download Agent Logs
def download_agentlogs_from_scwp_protected_vm():
    token = {}
    mydict = {}

    #CWP Prod URL
    envurl = 'https://scwp.securitycloud.symantec.com/dcs-service'

    # CWP REST API endpoint URL for auth function
    url = envurl + '/dcscloud/v1/oauth/tokens'

    print('Downloading Agent Logs initiated...')
    spinner = spinning_cursor()
    counterval = 0
    print("In progress : ")
    sys.stdout.write(next(spinner))
    sys.stdout.flush()
    # Add to payload and header your CWP tenant & API keys - client_id, client_secret, x-epmp-customer-id and x-epmp-domain-id
    payload = {'client_id': clientID, 'client_secret': clientsecret}
    header = {"Content-type": "application/json", 'x-epmp-customer-id': customerID, 'x-epmp-domain-id': domainID}
    response = requests.post(url, data=json.dumps(payload), headers=header)
    sys.stdout.write('\b')
    authresult = response.status_code
    token = response.json()
    if (authresult != 200):
        print (
            "\nAuthentication Failed. Did you replace the API keys in the code with your CWP API Keys? Check clientsecret, clientID, customerID, and domainID\n")
        exit()
    # Extracting auth token
    accesstoken = token['access_token']
    accesstoken = "Bearer " + accesstoken

    #Get Instance MDR ID from Instance ID
    urlgetassetdetails = envurl + '/dcscloud/v1/ui/assets?where=(instance_id=\'%s\')&fields=id' % instanceid

    headergetlog = {"Authorization": accesstoken, 'x-epmp-customer-id': customerID, 'x-epmp-domain-id': domainID,
                    "Content-Type": "application/json"}

    sys.stdout.write(next(spinner))
    sys.stdout.flush()
    response = requests.get(urlgetassetdetails, headers=headergetlog)
    sys.stdout.write('\b')
    assetRespContent = json.loads(response.content)
    assetid = assetRespContent["results"][0]["id"]

    #assetid = json.loads(resultarray.content)[0]["id"]

    # CWP REST API issue GET-LOG command

    urlgetlog = envurl + '/dcscloud/v1/agents/get-log'
    getlogpayload = [assetid]

    sys.stdout.write(next(spinner))
    sys.stdout.flush()
    response = requests.post(urlgetlog, data=json.dumps(getlogpayload), headers=headergetlog)
    sys.stdout.write('\b')
    apiresult = response.status_code

    if (apiresult != 200):
        print("\nFailed to issue command GET-LOG for agent %s\n" % assetid)
        exit()

    #CWP REST API GET AGENT LOG DETAILS FOR DEVICE

    urlgetagentlogdetails = envurl + '/dcscloud/v1/agents/%s/get-log-details?limit=1' % assetid
    sys.stdout.write(next(spinner))
    sys.stdout.flush()
    response = requests.get(urlgetagentlogdetails, headers=headergetlog)
    sys.stdout.write('\b')
    if (response.status_code != 200):
        print("\nFailed to get agent log details for agent %s\n" % assetid)
        exit()

    commandid = json.loads(response.content)[0]["command_id"]

    commandstate = json.loads(response.content)[0]["command_state"]

    #Check for command details

    urlgetcommanddetails = envurl + '/dcscloud/v1/agents/command/details/%s' % commandid


    while commandstate == 'Ready' or commandstate == 'InProgress':
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.5)

        if counterval % 20 == 0:
            response = requests.get(urlgetcommanddetails, headers=headergetlog)
            if (response.status_code != 200):
                print("\nFailed to get GET-LOG command details for agent %s\n" % assetid)
                exit()
            commandstate = json.loads(response.content)["command_state"]
        sys.stdout.write('\b')
        counterval = counterval + 1

    if commandstate == 'Succeeded':
        urldownloadlogs = envurl + '/dcscloud/v1/agents/download-log/%s' % commandid
        headergetlog = {"Authorization": accesstoken, 'x-epmp-customer-id': customerID, 'x-epmp-domain-id': domainID,
                        "Content-Type": "application/octet-stream"}
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        response = requests.get(urldownloadlogs, headers=headergetlog)
        sys.stdout.write('\b')
        result = response.status_code
        if (result == 200):
            # Agent download logs API was successful
            mydict = response.headers
            contentdisposition = mydict['content-disposition']
            regex = re.search(r'^(.*?)filename=(.*)$', contentdisposition)
            filename = regex.group(2)
            with open(filename, "wb") as code:
            # Save downloaded package to local file
                code.write(response.content)
                print ("\nAgent logs :-> '" + os.path.join(os.getcwd(),filename) + "' downloaded successfully for agent %s\n" % instanceid)
        else:
            print ("\nError while downloading agent logs for agent %s\n" % instanceid)
            exit()
    else:
        print('\nAgent Download Logs Failed...\n')



if __name__ == "__main__":
    if (len(sys.argv) < 5):
        print (
            "Insufficient number of arguments passed. Pass all 4 CWP API key parameters from 'Setting Page->API Keys' tab plus Instance ID of the VM (Found on Instance Details Page) for which agent logs need to be downloaded. Usage: python downloadagentlogs.py <Customer ID> <Domain ID> <Client Id> <Client Secret Key> <Instance ID>")
        exit()
    customerID = sys.argv[1]
    domainID = sys.argv[2]
    clientID = sys.argv[3]
    clientsecret = sys.argv[4]
    instanceid = sys.argv[5]
    download_agentlogs_from_scwp_protected_vm()
