import json
import urllib.request
import urllib.parse
import requests
import datetime as dt
import zlib
from datetime import datetime, timedelta
from urllib.request import urlopen

# Variables
requestUrl = "https://api-us.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesExport"
destinationFolder = "c:/temp/downloadedVulnerabilityData/" # Where should we store the downloaded files?
fileNamePrefix = "mdvm_export_" # What should we use as a prefix for the filename?
sasFilesKeepAlive = 3 # for how many hours should the files be accessible via shared access signature?  Default is 3, max is 24
intCounter = 0 # Counter Value that we're going to use for our filenames in the for each loop to generate unique names
downloadedFilesList = [] # an array that will hold the filenames that we're writing out to the disk

# function get_aadToken: Retrieves the AAD Token that we need to access the service
def get_aadToken():
    tenantId = "[Your Azure AD Tenant ID]"            
    appId = "[Your Azure AD App ID]"               
    appSecret = "[Your App Secret]"
 
    url = "https://login.microsoftonline.com/%s/oauth2/token" % (tenantId)
    resourceAppIdUri = 'https://api.securitycenter.windows.com'
    body = {
        'resource' : resourceAppIdUri,
        'client_id' : appId,
        'client_secret' : appSecret,
        'grant_type' : 'client_credentials'
    }
 
    data = urllib.parse.urlencode(body).encode("utf-8")
    req = urllib.request.Request(url, data)
    response = urllib.request.urlopen(req)
    jsonResponse = json.loads(response.read())
    return jsonResponse
    
# function softwareVulnerabilitiesExport: Gets download links for vulnerability export files
# Note: These files are in gzip format
def softwareVulnerabilitiesExport(aadToken, sasValidHours):
        headers = {
        'Content-Type' : 'application/json',
        'Authorization' : "Bearer " + aadToken
        }
        api_response = requests.get(requestUrl, headers=headers)
        json_response = api_response.json()
        #return the entire json response body so that we can decide what to extract in the calling function
        return json_response

# Get the json body returned from calling get_aadToken
aadTokenJson = get_aadToken()
aadToken = aadTokenJson["access_token"] # Extract the access_token
# Get the list of download Url's
sasFilesList = softwareVulnerabilitiesExport(aadToken,sasFilesKeepAlive)

# for each file that is returned from the api...
for downloadFileUrl in sasFilesList["exportFiles"]:
    try:
        print(downloadFileUrl)
        # create the destination file name
        destinationFileName = destinationFolder + fileNamePrefix + str(intCounter) + ".json"
        # request the file
        downloadFileRequest = urllib.request.urlopen(downloadFileUrl)
        # decompress the file
        downloadFileContent = zlib.decompress(downloadFileRequest.read(),16+zlib.MAX_WBITS)
        # write the file to the target
        with open(destinationFileName,'wb') as targetFile:
            targetFile.write(downloadFileContent)
        # add the filename to the downloaded files list
        downloadedFilesList.append(destinationFileName)
        # Increment the counter value
        intCounter += 1
    except:
        print("exception occurred while processing vulnerability file downloads")
# write out the filenames that we just downloaded
for filesWritten in downloadedFilesList:
    print(filesWritten)
