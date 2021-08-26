import boto3 
import requests
import ast
import json

account_no = "Mention the account no in which you are deploying this"

def public_events(event):
    event_name = event["detail"]['eventName']
    if event_name == "CreateQueue": 
        policy = event["detail"]['requestParameters']['attribute']['Policy']
        public_policy_finder(policy)
    elif event_name == "SetQueueAttributes":
        if event["detail"]['requestParameters']['attributeName'] == 'Policy':
            policy = event["detail"]['requestParameters']['attributeValue']
            public_policy_finder(policy)
    elif event_name == "CreateTopic":
        policy = event["detail"]['requestParameters']['attributes']['Policy']
        public_policy_finder(policy)
    elif event_name == "SetTopicAttributes":
        if event["detail"]['requestParameters']['attributeName'] == 'Policy':
            policy = event["detail"]['requestParameters']['attributeValue']
            public_policy_finder(policy)
    
    elif event_name == "SetRepositoryPolicy":
        policy = event["detail"]['requestParameters']['policyText']
        public_policy_finder(policy)
    elif event_name == "PutKeyPolicy":
        policy = event["detail"]['requestParameters']['policy']
        public_policy_finder(policy)
    elif event_name == "CreateKey":
        policy = event["detail"]['requestParameters']['policy']
        public_policy_finder(policy)
    elif event_name == "PutResourcePolicy":
        policy = event["detail"]['requestParameters']['resourcePolicy']
        public_policy_finder(policy)
    elif event_name == "PutKeyPolicy":
        policy = event["detail"]['requestParameters']['policy']
        public_policy_finder(policy)
    
    elif event_name == "CreateElasticsearchDomain":
        policy = event["detail"]['requestParameters']['accessPolicies']
        public_policy_finder(policy)
    elif event_name == "UpdateElasticsearchDomainConfig":
        policy = event["detail"]['requestParameters']['accessPolicies']
        public_policy_finder(policy)
    elif event_name == "SetVaultAccessPolicy":
        policy = event["detail"]['requestParameters']['policy']['policy']
        public_policy_finder(policy)
    
    else:
        return None 
    

        
def slack_alerts(policy):
    template = {}
    template['attachments'] = [{}]
    template['attachments'][0]['fallback'] = 'unable to display this message !'
    template['attachments'][0]['color'] = '#AF0000'
    template['attachments'][0]['pretext'] = "Public Resource Alerts"

    template['attachments'][0]['fields'] = [{"title": "Resource might me public via below policy"}]
    template['attachments'][0]['fields'].append({"title": "Policy"})
    template['attachments'][0]['fields'].append({"value": policy })

    json_template = json.dumps(template)
    requests.post(url='Mention Incoming webhook URL of Slack', data=json_template)
    



# Use this function if you want to scan your existing policies
def get_policy_json():
    iam = boto3.client('iam')
    p_paginator = iam.get_paginator('list_policies')
    p_page_iterator = p_paginator.paginate()
    for page in p_page_iterator:
        for i in page['Policies']:
            arn = i['Arn']
            policy = iam.get_policy(
                PolicyArn = arn
            )
            policy_version = iam.get_policy_version(
                PolicyArn = arn, 
                VersionId = policy['Policy']['DefaultVersionId']
            )

            policy_json = json.dumps(policy_version['PolicyVersion']['Document'])
            print(policy_json)
            #public_policy_finder(policy_json)


def public_policy_finder(policy):
    policy = policy.replace('\"', '"')
    policy = policy.replace("\n", "")
    policy1 = policy
    policy = ast.literal_eval(policy)
    print(policy1)
           
    #print(policy)
    for i in policy['Statement']:
        if "Principal" in i:
            if "AWS" in i['Principal'] and "*" in i['Principal']['AWS']:
                if 'Condition' in i:
                    if 'AWS:SourceOwner' or 'AWS:SourceArn' or 'AWS:SourceAccount' in i['Condition']['StringEquals']:
                        print("This resource is not public")
                    elif 'ArnLike' in i['Condition']:
                        print("This resource is not public")
                    else:

                        condition = i["Condition"]
                        print("These actions are allowed : {0}".format(i['Action']))
                        if 'Resource' in i:
                            print("On this resource: {0}".format(i['Resource']))
                        print("This resourse can be accessed via {0}".format(i["Condition"]))
                        print(policy)
                        slack_alerts(policy1)
                else:
                    pri = i['Principal']
                    print(i['Principal'])
                    print("These actions are allowed : {0}".format(i['Action']))
                    if 'Resource' in i:
                        print("On this resource: {0}".format(i['Resource']))
                    print(policy)
                    slack_alerts(policy1)
            
            elif "Service" in i['Principal']:
                if 'Condition' in i:
                    if 'AWS:SourceOwner' or 'AWS:SourceArn' or 'AWS:SourceAccount' in i['Condition']['StringEquals']:
                        print("This resource is not public")
                    elif 'ArnLike' in i['Condition']:
                        print("This resource is not public")
                    else:

                        service = i['Principal']['Service']
                        print(service)
                        condition = i["Condition"]
                        print("These actions are allowed : {0}".format(i['Action']))
                        if 'Resource' in i:
                            print("On this resource: {0}".format(i['Resource']))
                        print("This resourse can be accessed via {0}".format(i["Condition"]))
                        slack_alerts(policy)
                else:

                    service = i['Principal']['Service']
                    print(service)
                    print("These actions are allowed : {0}".format(i['Action']))
                    if 'Resource' in i:
                        print("On this resource: {0}".format(i['Resource']))
                    slack_alerts(policy)

            elif "*" in i['Principal']:
                if 'Condition' in i:
                    if 'AWS:SourceOwner' or 'AWS:SourceArn' or 'AWS:SourceAccount' in i['Condition']['StringEquals']:
                        print("This resource is not public")
                    elif 'ArnLike' in i['Condition']:
                        print("This resource is not public")
                    else:
                        condition = i["Condition"]
                        print("These actions are allowed : {0}".format(i['Action']))
                        if 'Resource' in i:
                            print("On this resource: {0}".format(i['Resource']))
                        print("This resourse can be accessed via {0}".format(i["Condition"]))
                        slack_alerts(policy)
                else:

                    pri = i['Principal']
                    print("this policy made x resource public")
                    print("These actions are allowed : {0}".format(i['Action']))
                    if 'Resource' in i:
                        print("On this resource: {0}".format(i['Resource']))
                    slack_alerts(policy)
            
            else:
                for i in i['Principal']['AWS']:
                    j = i.split(':')
                    account_id = i[4]
                    if account_id != account_no:
                        if 'Condition' in i:
                            if 'AWS:SourceOwner' or 'AWS:SourceArn' or 'AWS:SourceAccount' in i['Condition']['StringEquals']:
                                print("This resource is not public")
                            elif 'ArnLike' in i['Condition']:
                                print("This resource is not public")
                            else:
                                condition = i["Condition"]
                                print("These actions are allowed : {0}".format(i['Action']))
                                if 'Resource' in i:
                                    print("On this resource: {0}".format(i['Resource']))
                                print("This resourse can be accessed via {0}".format(i["Condition"]))
                                slack_alerts(policy)
                        else:

                            print(i)
                            print("Given access to the external account")
                            print("These actions are allowed : {0}".format(i['Action']))
                            if 'Resource' in i:
                                print("On this resource: {0}".format(i['Resource']))
                            slack_alerts(policy)

            
        
        else:
            return None




def lambda_handler(event, context):
    public_events(event)
