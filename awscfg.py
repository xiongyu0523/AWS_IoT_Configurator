import sys
import boto3
import botocore
import argparse
import json

def createNewThing():

    response = iot.list_things()
    for thing in response['things']:
        if thing['thingName'] == args.ThingName:
            print(f'We already have {args.ThingName}')
            return False

    response = iot.create_thing(
        thingName=args.ThingName,
        thingTypeName="MCUIoTGatewayType",
        attributePayload={
            "attributes": {
                "Owner": args.owner,
                "Version" : args.version,
                "WIFI" : args.wifi
            },
        },
    )

    print(f'The {args.ThingName} is created')
    return True

def createAWSIoTCertificate():

    response = iot.create_keys_and_certificate(
        setAsActive=True
    )

    certificateId = response['certificateId']

    f = open(certificateId[:10]+'-certificate.pem.crt', 'wt')
    f.write(response['certificatePem'])
    f.close()    
    
    f = open(certificateId[:10]+'-public.pem.key', 'wt')
    f.write(response['keyPair']['PublicKey'])
    f.close()    
    
    f = open(certificateId[:10]+'-private.pem.key', 'wt')
    f.write(response['keyPair']['PrivateKey'])
    f.close()

    return response['certificateArn']

def AttachPolicyAndCertificate(CertificateArn):
	response = iot.attach_policy(
			policyName = 'MCUIoTGatewayPolicy',
			target = CertificateArn
	)

	response = iot.attach_thing_principal(
			thingName = args.ThingName,
			principal = CertificateArn
	)

def createThingType():
    'Create MCUIoTGatewayType when it is NOT existed'
    response = iot.create_thing_type(
        thingTypeName ="MCUIoTGatewayType", 
        thingTypeProperties={
            'searchableAttributes': [
                'Owner', 'Version', 'WIFI'
            ]
        }
    )

def createIoTPolicy():
    'Create MCUIoTGatewayPolicy when it is NOT existed.'
    try:
        response = iot.create_policy(
            policyName="MCUIoTGatewayPolicy", 
            policyDocument="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"iot:*\",\"Resource\":\"*\"}]}"
        )
    except iot.exceptions.ResourceAlreadyExistsException:
        print("We already have MCUIOTGatewayPolicy")
    else:
        print("The MCUIoTGatewayPolicy is created")

def createDisconnectRule():
    response = iot.create_topic_rule(
        ruleName='Disconnect',
        topicRulePayload={
            'sql': 'SELECT eventType as state.reported.gw_info.server FROM \'$aws/events/presence/disconnected/+\' WHERE clientInitiatedDisconnect = false',
            'actions': [
                {
                    'republish': {
                        'roleArn': f'arn:aws-cn:iam::{AccoundID}:role/Republish@iot',
                        'topic': '$$aws/things/${topic(5)}/shadow/update'
                    },
                },
            ],
            'ruleDisabled': False,
            'awsIotSqlVersion': '2016-03-23',
        }
    )

def createIAMRoleforCognito():
    
    assume_role_policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "Federated": "cognito-identity.amazonaws.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": "cn-north-1:8dba4b4b-2a6d-4d9b-bcc9-08a02e2ca1bd"
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "unauthenticated"
                }
            }
        }]
    })

    try:
        response = iam.create_role(
            RoleName='Cognito_MCUIoTGatewayIdentityPoolUnauth_Role',
            AssumeRolePolicyDocument=assume_role_policy_document,
        )
    except iam.exceptions.EntityAlreadyExistsException:
        print('We already have Cognito_MCUIoTGatewayIdentityPoolUnauth_Role')
        
        response = iam.get_role(
            RoleName='Cognito_MCUIoTGatewayIdentityPoolUnauth_Role'
        )
    else:
        print('The Cognito_MCUIoTGatewayIdentityPoolUnauth_Role is created')

    response = iam.attach_role_policy(
        RoleName='Cognito_MCUIoTGatewayIdentityPoolUnauth_Role', 
        PolicyArn= f'arn:aws-cn:iam::{AccoundID}:policy/MCUIoTGatewayPolicy'
    )

    # add inline policy
    policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "mobileanalytics:PutEvents",
                    "cognito-sync:*"
                ],
                "Resource": [
                    "*"
                ]
            }
        ]
    })
    response = iam.put_role_policy(
        RoleName='Cognito_MCUIoTGatewayIdentityPoolUnauth_Role',
        PolicyName='inlinePolicy',
        PolicyDocument=policy_document
    )

    assume_role_policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "Federated": "cognito-identity.amazonaws.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": "cn-north-1:8dba4b4b-2a6d-4d9b-bcc9-08a02e2ca1bd"
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "authenticated"
                }
            }
        }]
    })

    try:
        response = iam.create_role(
            RoleName='Cognito_MCUIoTGatewayIdentityPoolAuth_Role',
            AssumeRolePolicyDocument=assume_role_policy_document,
        )
    except iam.exceptions.EntityAlreadyExistsException:
        print('We already have Cognito_MCUIoTGatewayIdentityPoolAuth_Role Role')
        
        response = iam.get_role(
            RoleName='Cognito_MCUIoTGatewayIdentityPoolAuth_Role'
        )
    else:
        print('The Cognito_MCUIoTGatewayIdentityPoolAuth_Role role is created')

    response = iam.attach_role_policy(
        RoleName='Cognito_MCUIoTGatewayIdentityPoolAuth_Role', 
        PolicyArn= f'arn:aws-cn:iam::{AccoundID}:policy/MCUIoTGatewayPolicy'
    ) 

    policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "mobileanalytics:PutEvents",
                    "cognito-sync:*",
                    "cognito-identity:*"
                ],
                "Resource": [
                    "*"
                ]
            }
        ]
    })
    response = iam.put_role_policy(
        RoleName='Cognito_MCUIoTGatewayIdentityPoolAuth_Role',
        PolicyName='inlinePolicy',
        PolicyDocument=policy_document
    )

def createIAMPolicy():

    policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iot:*"
                ],
                "Resource": [
                    "*"
                ]
            }
        ]
    })

    try:
        response = iam.create_policy(
            PolicyName='MCUIoTGatewayPolicy',
            PolicyDocument=policy_document,
        )
    except iam.exceptions.EntityAlreadyExistsException:
        print('We already have MCUIoTGatewayPolicy Policy')
    else:
        print('The MCUIoTGatewayPolicy IAM Policy is created')

def createIAMRoleForIoTRule():

    assume_role_policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "iot.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }]
    })

    try:
        response = iam.create_role(
            RoleName='Republish@iot',
            AssumeRolePolicyDocument=assume_role_policy_document,
        )
    except iam.exceptions.EntityAlreadyExistsException:
        print('We already have Republish@iot Role')
    else:
        print('The Republish@iot role is created')
    
    # attach neccessary managed policy
    response = iam.attach_role_policy(
        RoleName='Republish@iot', 
        PolicyArn='arn:aws-cn:iam::aws:policy/service-role/AWSIoTLogging'
    )
    response = iam.attach_role_policy(
        RoleName='Republish@iot', 
        PolicyArn='arn:aws-cn:iam::aws:policy/service-role/AWSIoTRuleActions'
    )
    response = iam.attach_role_policy(
        RoleName='Republish@iot', 
        PolicyArn='arn:aws-cn:iam::aws:policy/service-role/AWSIoTThingsRegistration'
    )


def createCognitoIdentityPool():
    'Create MCUIoTGatewayIdentityPool if it is NOT existed. When a new Pool is created, the APP must load a different properties file'
    
    # Since we can create many pools using the same name, we need first check if it is existed.
    response = cognito.list_identity_pools(MaxResults=60)
    for pool in response['IdentityPools']:
        if pool['IdentityPoolName'] == 'MCUIoTGatewayIdentityPool':
            print('We already have MCUIoTGatewayIdentityPool')
            return

    response = cognito.create_identity_pool(
        IdentityPoolName = 'MCUIoTGatewayIdentityPool',
        AllowUnauthenticatedIdentities = True
    )

    ID = response['IdentityPoolId']

    cognito.set_identity_pool_roles(
        IdentityPoolId=ID,
        Roles={
            'unauthenticated': f'arn:aws-cn:iam::{AccoundID}:role/Cognito_MCUIoTGatewayIdentityPoolUnauth_Role',
            'authenticated' : f'arn:aws-cn:iam::{AccoundID}:role/Cognito_MCUIoTGatewayIdentityPoolAuth_Role'
        }
    )

    print('The MCUIoTGatewayIdentityPool is created')

if __name__ == "__main__":

    # Let's deal with arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("ThingName", help="the name of the thing that you want to create")
    parser.add_argument("-o", "--owner", default="NOBODY", help="the owner of the thing")
    parser.add_argument("-v", "--version", default="1.0", help="the version of the thing")
    parser.add_argument("-w", "--wifi", default="ESP8266", help="the wifi module used")
    args = parser.parse_args()

    iot = boto3.client('iot')
    iam = boto3.client('iam')
    sts = boto3.client('sts')
    cognito = boto3.client('cognito-identity')
    AccoundID = sts.get_caller_identity()['Account']

    createIoTPolicy()
    createThingType()
    createIAMRoleForIoTRule()
    createDisconnectRule()
    createIAMPolicy()
    createIAMRoleforCognito()
    createCognitoIdentityPool() 
    
    if createNewThing():
        AttachPolicyAndCertificate(createAWSIoTCertificate())
    
