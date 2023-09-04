#!/bin/bash

# A script to generate and export Fortify scan results for the applications in SSC.
# Script requires jq for parsing the json responses. See example of how to install on debian linux below:
# sudo apt install -y jq
# After downloading fcli, here is how you start a session below:
# Example: fcli ssc session login --url https://your_ssc/ -k --user nathan_bennett --password ''
# Does require you to login and grab your session cookie from storage to download the reports to csv
# This script will store two files in the working directory to store the session cookies. Delete after use.
# Will take around 5 min. to complete.

# Create the scan_admin session to interact with Fortify fcli *Remember to put scan admin's password below
fcli ssc session login --url https://your_ssc/ -k --user scan_admin --password $ssc_passwd #add environment variable for ssc passwd

# Gather all of the appversion for the forloop. Labeled files to name the exports when converted to CSV.
files="$(fcli ssc appversion list | awk 'NR > 1 { printf "%s\n", $1 }')"
limit="$(echo "${files[@]}" | wc -l)"

# Timestamp is needed to gather the number of exports in SSC
timestamp=$(date +%s)
echo $timestamp
echo ""

# Forloop to generate all app vunerability exports in SSC
for file in $files
do
	payload='{"type":"EXPORT_TO_CSV","actionResponse":true,"values":{"filename":"'
	payload+=$file
	payload+='.csv","note":null,"datasetname":"Audit","appversionid":'
	payload+=$file
	#filterset may need to be changed depending on your specific web request
	payload+=',"start":0,"limit":-1,"filterset":"a243b195-0a59-3f8b-1403-d55b7a7d78e6","orderby":"friority"}}'
	fcli ssc rest call -X POST /api/v1/dataExports/action -d $payload
done

# Gather all of the ids of the generated reports to iterate through
dataexports="/api/v1/dataExports?&start=0&q=datasetName%3A%22Audit%22&limit=${limit}&orderby=-generationDate&ts=${timestamp}"
ids="$(fcli ssc rest call -X GET $dataexports | jq '.[].data[].id')"

# Login with scan_admin and pull cookie for downloads below. Note: You receive one cookie before authentication that is why there are two requests.
curl -c cookie-jar.txt https://your_ssc/
cewkie="JSESSIONID="
cewkie+=$(cat cookie-jar.txt | awk '{ printf $7 }' | cut -c 9-)                                                  # Add username, site, and Add URL encoded Password after "password=" **Remember can use cyberchef or burpsuite to urlencode
curl -k --cookie $cewkie -c cookie-jar1.txt -X POST https://your_ssc/j_spring_security_check -d 'hash=https%3A%2F%2Fyour_ssc%3A443%2F&j_username=scan_admin&j_password=url_encoded_passwd'
cewkie="JSESSIONID="
cewkie+=$(cat cookie-jar1.txt | awk '{ printf $7 }' | cut -c 9-)

# Forloop to run through the generated CSV files and download them to the working directory
for id in $ids
do
	mat="$(fcli ssc rest call -X POST /api/v1/fileTokens -d '{"fileTokenType":3}' | jq -r '.[].data.token')"
 	sscaddress="https://your_ssc/transfer/dataExportDownload.html?mat=${mat}&id=${id}"
	#fcli ssc rest call -X GET $sscaddress >> $id.csv # Need to come back to this had issues parsing this request because of the format response
	curl -k --cookie $cewkie -X GET $sscaddress >> $id.csv
done

# Last piece is to merge all of the CSV files into one
cat *.csv | sort -u > Fortify_merged.csv
