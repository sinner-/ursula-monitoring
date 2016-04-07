#!/usr/bin/env python
#
# Calls neutron agent api, checks for routers that have multiple active l3 agents
#
# return CRITICAL if any routers found with more than one active l3 agent
#
# Sina Sadeghi <ssadeghi@au1.ibm.com>

import argparse
import sys
import os
import json
import requests


STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2

timeout = 30

def request(url, method='GET', retries=2, **kwargs):

    r = None
    try:
        for i in range(retries + 1):
            if i > 0:
                time.sleep(2)
            r = requests.request(method, url, **kwargs)
            if r.status_code:
                break
    except requests.exceptions.RequestException as e:
        print("%s returned %s" % (url, e))

    return r.json()


def check_router(router, router_agents):

    agent_dictionary = {}
    active_agent = False
    multiple_active_agents = False

    for agent in router_agents['agents']:
        if 'ha_state' not in agent.keys():
            return False
        if active_agent and agent['ha_state'] == 'active':
            multiple_active_agents = True
            print("Multiple active l3 agents for router %s" % router['id'])
        if agent['ha_state'] == 'active':
            active_agent = True

    return multiple_active_agents

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user', default=os.environ['OS_USERNAME'])
    parser.add_argument('-p', '--password', default=os.environ['OS_PASSWORD'])
    parser.add_argument('-t', '--tenant', default=os.environ['OS_TENANT_NAME'])
    parser.add_argument('-a', '--auth-url', default=os.environ['OS_AUTH_URL'])
    args = parser.parse_args()

    url = args.auth_url + '/tokens'
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    data = json.dumps(
        {
            'auth': {
                'tenantName': args.tenant,
                'passwordCredentials': {
                    'username': args.user,
                    'password': args.password
                }
            }
        })

    r = request(url, 'POST', 4, data=data, headers=headers)
    token = None
    if r:
        access = r['access']
        token = access['token']['id']

    if not token:
        sys.exit(STATE_CRITICAL)

    endpoints = {}
    for service in access['serviceCatalog']:
        for endpoint in service['endpoints']:
            endpoints[service['name']] = endpoint.get('internalURL')

    headers = {'Accept': 'application/json', 'X-Auth-Project-Id': args.tenant,
               'X-Auth-Token': token}

    endpoint = endpoints['neutron'] + '/v2.0/routers.json'
    router_list = request(endpoint, headers=headers )
    if not router_list :
        print("API call failed")
        sys.exit(STATE_WARNING)

    exit_crit = False
    
    for router in router_list['routers']:

        router_id = router['id']

        endpoint = endpoints['neutron'] + '/v2.0/routers/' + router_id + '/l3-agents.json'
        router_agents = request(endpoint, headers=headers)

        multiple_active_agents = check_router(router, router_agents)
        if multiple_active_agents:
            exit_crit = True

    if exit_crit:
        print("Multiple active l3 agents found on at least one router")
        sys.exit(STATE_CRITICAL)
    else:
        print("No routers with multiple active l3 agents")
        sys.exit(STATE_OK)

if __name__ == "__main__":
    main()
