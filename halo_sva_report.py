# WARNING: This script takes a long time to execute if you have a high count
#          of active servers.
# Author: Sean Nicholson
# Version 1.0
# Date 04.07.2017
##############################################################################

# Import Python Modules
import json, csv
import cloudpassage
import yaml
import time
global api_session


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

# 
def get_scan_data(session):
        out_file = "Vunerability_Report_" + time.strftime("%Y%m%d-%H%M%S") + ".csv"
        ofile  = open(out_file, "w")
        halo_server_list = get_halo_servers_id(session)
        get_halo_servers_scans= cloudpassage.HttpHelper(session)
        ofile.write('AWS Account Number,AWS Instance ID,Package Name,Package Version,CVE,CVE Rating,CVE Information\n')
        server_count = 1
        total_servers = len(halo_server_list)
        for server in halo_server_list:
            #print server['halo_server_id']
            print "Processing {0} of {1} servers".format(server_count, total_servers)
            server_count+=1
            api_url = '/v1/servers/' + server['halo_server_id'] + '/svm'
            current_server=get_halo_servers_scans.get(api_url)
            #print current_server
            if 'scan' in current_server:
                current_findings = current_server['scan']['findings']
                #print current_findings
                for finding in current_findings:
                    if finding['status'] == 'bad':
                        finding_cves = finding['cve_entries']
                        for cve in finding_cves:
                            if float(cve['cvss_score']) >= 7.0:
                                cve_link="https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve['cve_entry']
                                row="'{0}',{1},{2},{3},{4},{5},{6}\n".format(server['aws_account_id'],server['aws_instance_id'],finding['package_name'],finding['package_version'],cve['cve_entry'],'High',cve_link)
                                ofile.write(row)
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
