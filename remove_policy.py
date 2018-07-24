##############################################################################
# Halo API Remove policy from groups
# Author: Sean Nicholson
# Version 1.0.0
# Date 07.19.2018
# v 1.0.0 - initial release
##############################################################################


import cloudpassage, yaml, base64, requests, json



def create_api_session(session):
    config_file_loc = "cloudpassage.yml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)
    session = cloudpassage.HaloSession(config_info.key_id, config_info.secret_key)
    return session

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

def remove_policy_from_group(session):
    headers = get_headers()
    with open('cloudpassage.yml') as config_settings:
        script_options_info = yaml.load(config_settings)
        remove_policy_id = script_options_info['defaults']['remove_policy_id']
        #remove_policy_type = script_options_info['defaults']['remove_policy_type']
    api_results_list = cloudpassage.HttpHelper(session)
    list_of_groups = api_results_list.get_paginated("/v1/groups?per_page=1000", "groups", 20)
    policy_check = remove_policy_type + "_policy_ids"
    payload = {"group":{"fim_policy_ids":[str(remove_policy_id)]}}
    payload_win = {"group":{"windows_fim_policy_ids":[str(remove_policy_id)]}}
    counter = 0
    removed_policy = 0
    policy_removed_from = []
    for group in list_of_groups:
        removed_policy = 0
        new_policy = []
        new_win_policy = []
        requests_url = '/v1/groups/' + group['id']
        if group['fim_policy_ids']:
            for policy in group['fim_policy_ids']:
                #print policy
                if policy == remove_policy_id:
                    print "found a match"
                    print "Removed {0} {1} from {2}".format(policy_check,remove_policy_id,group['name'])
                    removed_policy += 1
                    counter +=1
                else:
                    new_policy.append(policy)
            if removed_policy > 0:
                payload = {"group":{"fim_policy_ids": new_policy}}
                api_results_list.put(requests_url, payload)
                policy_removed_from.append({"group name" : str(group['name']), "group ID" : str(group['id']), "group path" : str(group['group_path'])})

        if group['windows_fim_policy_ids']:
            print "starting win checks"
            for policy in group['windows_fim_policy_ids']:
                #print policy
                if policy == remove_policy_id:
                    print "found a match"
                    print "Removed {0} {1} from {2}".format(policy_check,remove_policy_id,group['name'])
                    removed_policy += 1
                    counter +=1
                else:
                    new_win_policy.append(policy)
            if removed_policy > 0:
                payload_win = {"group":{"windows_fim_policy_ids": new_win_policy}}
                #print payload_win
                api_results_list.put(requests_url, payload_win)
                policy_removed_from.append({"group name" : str(group['name']), "group ID" : str(group['id']), "group path" : str(group['group_path'])})


    #if you got here, no match found
    if counter > 0:
        print "Removed {0} - {1} from {2} groups".format(policy_check, str(remove_policy_id), counter)
        print policy_removed_from
    else:
        print "Policy removed from 0 groups"

if __name__ == "__main__":
    api_session = None
    api_session = create_api_session(api_session)
    remove_policy_from_group(api_session)
