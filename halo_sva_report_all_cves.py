# WARNING: This script takes a long time to execute if you have a high count
#          of active servers.
# Author: Sean Nicholson
# Version 1.2
# Date 04.12.2017
##############################################################################

# Import Python Modules
import json, csv, base64, requests, os
import cloudpassage
import yaml
import time
from time import sleep
global api_session

# Set variable types
user_credential_b64 = ''
headers = {}
api_key_description = ''


# Define Methods
def create_api_session(session):
    config_file_loc = "cloudpassage.yml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)
    return session

def byteify(input):
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def get_headers():
    # Create headers
    with open('cloudpassage.yml') as config_settings:
        api_info = yaml.load(config_settings)
        api_key_token = api_info['defaults']['key_id'] + ":" + api_info['defaults']['secret_key']
        api_request_url = "https://" + api_info['defaults']['api_hostname'] + ":443"
    user_credential_b64 = "Basic " + base64.b64encode(api_key_token)
    reply = get_access_token(api_request_url, "/oauth/access_token?grant_type=client_credentials",
                             {"Authorization": user_credential_b64})
    reply_clean = reply.encode('utf-8')
    headers = {"Content-type": "application/json", "Authorization": "Bearer " + reply_clean}
    #print headers
    return headers

# Request Bearer token and return access_token
def get_access_token(url, query_string, headers):
    retry_loop_counter = 0
    while retry_loop_counter < 5:
        reply = requests.post(url + query_string, headers=headers)
        #print reply.status_code
        if reply.status_code == 200:
            return reply.json()["access_token"]
            retry_loop_counter = 10
        else:
            retry_loop_counter += 1
            time.sleep(30)

#
def get_scan_data(session):
    headers = get_headers()
    if not os.path.exists("reports"):
        os.makedirs("reports")
    out_file = "reports/Vunerability_Report_" + time.strftime("%Y%m%d-%H%M%S") + ".csv"
    ofile  = open(out_file, "w")
    halo_server_list = get_halo_servers_id(session)
    get_halo_servers_scans= cloudpassage.HttpHelper(session)
    ofile.write('AWS Account Number,AWS Instance ID,Package Name,Package Version,CVE,CVE Rating,CVE Information\n')
    server_count = 1
    total_servers = len(halo_server_list)
    for server in halo_server_list:
        retry_loop_counter = 0
        #print server['halo_server_id']
        print "Processing {0} of {1} servers".format(server_count, total_servers)
        server_count+=1
        api_url = '/v1/servers/' + server['halo_server_id'] + '/svm'
        requests_url = 'https://api.cloudpassage.com:443/v1/servers/' + server['halo_server_id'] + '/svm'
        #print requests_url
        #current_server=get_halo_servers_scans.get(api_url)
        while retry_loop_counter < 5:
            data = requests.request("GET", requests_url, data=None, headers=headers)
            status_code = str(data.status_code)
            #print status_code
            if status_code == "200":
                data = data.json()
                #print data
                #print current_server
                if 'scan' in data:
                    current_findings = data['scan']['findings']
                    #print current_findings
                    for finding in current_findings:
                        if finding['status'] == 'bad':
                            finding_cves = finding['cve_entries']
                            for cve in finding_cves:
                                #if float(cve['cvss_score']) >= 7.0:
                                cve_link="https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve['cve_entry']
                                #print cve['cve_entry']
                                row="'{0}',{1},{2},{3},{4},{5},{6}\n".format(server['aws_account_id'],server['aws_instance_id'],finding['package_name'],finding['package_version'],cve['cve_entry'],'High',cve_link)
                                ofile.write(row)
                retry_loop_counter = 6
            elif status_code == "401":
                headers = get_headers()
                retry_loop_counter += 1
            elif status_code:
                print "Response Error:{0}, pausing 60 secs, then retrying".format(status_code)
                retry_loop_counter += 1
                time.sleep(60)
    ofile.close()



# Query Halo API /v1/servers to get list of servers and extract Instance ID,
# AWS Account ID, and Halo Server ID
def get_halo_servers_id(session):
    old_agent_count = 0
    get_halo_servers_list = cloudpassage.HttpHelper(session)
    reply=get_halo_servers_list.get_paginated("/v1/servers?state=active","servers",15)
    halo_server_id_list=[]
    for server in reply:
        if 'aws_ec2' in server:
            ec2_data = server['aws_ec2']
            halo_server_id_list.append({'halo_server_id':server['id'], 'aws_instance_id':ec2_data['ec2_instance_id'], 'aws_account_id': ec2_data['ec2_account_id']})
        elif server['server_label'] and "_" in server['server_label']:
            server_label = server['server_label']
            server_label_parts = server_label.split("_")
            #print server_label_parts[1]
            #old_agent_count += 1
            server_label_account = server_label_parts[0]
            server_label_isntance = server_label_parts[1]
            halo_server_id_list.append({'halo_server_id':server['id'], 'aws_instance_id':server_label_isntance, 'aws_account_id': server_label_account})
    halo_instance_id_list = byteify(halo_server_id_list)
    print "Halo Server ID and AWS Account ID Lookup Complete " + time.strftime("%Y%m%d-%H%M%S")
    return halo_instance_id_list




if __name__ == "__main__":
    api_session = None
    api_session = create_api_session(api_session)
    get_scan_data(api_session)
