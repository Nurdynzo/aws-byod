import boto3
import os
import uuid
import json
import time
import socket
from datetime import datetime

# Constants
DOMAIN_TABLE_NAME = os.environ.get('DOMAIN_TABLE_NAME')
ALB_ARN = os.environ.get('ALB_ARN')
ALB_DNS = os.environ.get('ALB_DNS')
TARGET_GROUP_ARN = os.environ.get('TARGET_GROUP_ARN')
HTTPS_LISTENER_ARN = os.environ.get('HTTPS_LISTENER_ARN')

# Initialize AWS clients
dynamodb = boto3.resource("dynamodb")
domains_table = dynamodb.Table(DOMAIN_TABLE_NAME)
acm = boto3.client('acm')
elbv2 = boto3.client('elbv2')

def lambda_handler(event, context):
    try:
        http_method = event['httpMethod']
        # Handle OPTIONS request for CORS preflight
        if http_method == 'OPTIONS':
            return build_cors_preflight_response()
        path = event.get('path', '')
        
        # Route the request
        if http_method == 'POST' and path == '/register-domain':
            return register_domain(json.loads(event['body']))
        elif http_method == 'POST' and path == '/validate':
            return validate(json.loads(event['body']))
        elif http_method == 'POST' and path == '/check-status':
            return check_status(json.loads(event['body']))
        elif http_method == 'POST' and path == '/update-alb':
            return update_alb(json.loads(event['body']))
        elif http_method == 'GET' and path == '/health':
            return health_check()
        else:
            return build_response(405, {'message': 'Method Not Allowed'})
    
    except Exception as e:
        return build_response(500, {'url_message': str(e)})


def register_domain(domain_data):
    domain_name = domain_data['domain_name']

    # Check if domain already exists
    domain_check = domains_table.get_item(Key={'domain_name': domain_name})
    if 'Item' in domain_check and domain_check['Item']['domain_name'] == domain_name:
        item = {
            'message': 'Domain already registered',
            'domain': domain_name,
            'status': domain_check['Item']['status']
        }
        return build_response(409, item)
    # Create a new record
    domain_record = {
        'domain_name': domain_name,
        'status': 'pending'
    }
    # Save to DynamoDB
    domains_table.put_item(Item=domain_record)
    try:
        # Request certificate
        certificate_response = request_certificate(domain_name)
        domain_record.update({
            'certificate_arn': certificate_response['CertificateArn'],
            'status': 'PENDING_VALIDATION'
        })

        # Update record
        domains_table.put_item(Item=domain_record)

        item = {
            'message': 'Domain registration initiated',
            'domain': domain_name,
            'status': domain_record['status']
        }

        return build_response(201, item)

    except Exception as e:
        # Update record with error
        domain_record['status'] = 'error'
        domain_record['error_message'] = str(e)
        domains_table.put_item(Item=domain_record)
        
        return build_response(500, {'cert_error': domain_record['error_message']})

def validate(domain_data):
    domain_name = domain_data['domain_name']

    try:
        cert_arn = domains_table.get_item(Key={'domain_name': domain_name})
        domain_record = cert_arn['Item']
        certificate_arn = domain_record['certificate_arn']

        # Extract validation options
        cert_details = acm.describe_certificate(CertificateArn=certificate_arn)
        cert_validations = cert_details['Certificate']['DomainValidationOptions']
        validation_record = cert_validations[0]['ResourceRecord']
        domain_record.update({
            'name': validation_record['Name'],
            'type': validation_record['Type'],
            'value': validation_record['Value'],
            'status': cert_details['Certificate']['Status']
        })
        # Update record
        domains_table.put_item(Item=domain_record)

        item = {
            'message': 'Domain registration initiated',
            'domain': domain_name,
            'status': domain_record['status'],
            'alb_dns': ALB_DNS
        }
        item.update({
            'name': domain_record['name'],
            'CNAME': domain_record['type'],
            'value': domain_record['value']
        })

        return build_response(201, item)

    except Exception as e:
        return build_response(500, {'error': str(e)})

def check_status(domain_data):
    domain_name = domain_data['domain_name']
    cert_arn = domains_table.get_item(Key={'domain_name': domain_name})
    domain_record = cert_arn['Item']
    certificate_arn = domain_record['certificate_arn']

    try:
        cert_details = acm.describe_certificate(CertificateArn=certificate_arn)
        current_status = cert_details['Certificate']['Status']
        check_a_record =  verify_a_record(ALB_DNS, domain_name)
            
            # Update status if certificate status has changed
        # if current_status == 'ISSUED' and check_a_record == True  and domain_record['status'] != 'PENDING_VALIDATION':
        if current_status == 'ISSUED' and check_a_record == 'done':
            domain_record['status'] = 'ISSUED'
            # domains_table.put_item(Item=domain_record)
        # elif current_status == 'PENDING_VALIDATION' and check_a_record == False and domain_record['status'] != 'PENDING_VALIDATION':
        elif current_status == 'PENDING_VALIDATION' and check_a_record == 'pending':
            domain_record['status'] = 'PENDING_VALIDATION'
        elif current_status == 'ISSUED' and check_a_record == 'pending':
            domain_record['status'] = 'PENDING_VALIDATION'
        
        domain_record.update({
            'status': domain_record['status'],
            'A_status': check_a_record,
            'CNAME_status': domain_record['status']
        })
        domains_table.put_item(Item=domain_record)

        item = {
            'domain': domain_name,
            'message': 'Domain registration initiated',
            'status': domain_record['status'],
            'alb_dns': ALB_DNS,
            'name': domain_record['name'],
            'CNAME': domain_record['type'],
            'value': domain_record['value'],
            'A_status': check_a_record,
            'CNAME_status': current_status
        }

        return build_response(201, item)
    except Exception as e:
        return build_response(500, {'error': str(e)})

def update_alb(domain_data):
    domain_name = domain_data['domain_name']
    listeners = elbv2.describe_rules(ListenerArn=HTTPS_LISTENER_ARN)
    priorities = [int(rule['Priority']) for rule in listeners['Rules'] if rule['Priority'] != 'default']
    new_priority = max(priorities) + 1 if priorities else 1

    # Create new rule only if it doesn't already exist
    try:
        cert_arn = domains_table.get_item(Key={'domain_name': domain_name})
        domain_record = cert_arn['Item']
        certificate_arn = domain_record['certificate_arn']
        if domain_exists_in_alb(ALB_ARN, domain_name):
            return build_response(409, {'error': 'Domain already registered'})
        else:
            cert_response = certificate_alb_attachment(HTTPS_LISTENER_ARN, certificate_arn)
            alb_response = domain_alb_attachment(domain_name, HTTPS_LISTENER_ARN, TARGET_GROUP_ARN, new_priority)
            domain_record['alb_status'] = 'attached'
            # Update record
            domains_table.put_item(Item=domain_record)
            item = {
                'alb_attachment': 'Done',
                'certificate_attachment': 'Done',
                'alb_status': 'completed'
            }
            return build_response(201, item)
    except Exception as e:
        return build_response(500, {'error': str(e)})

def health_check():
    item = {
        'domain': "byod app",
        'message': 'Domain registration',
        'status': "healthy"
    }

    return build_response(200, item)


def domain_exists_in_alb(alb_arn, domain_name):
    elbv2 = boto3.client('elbv2')
    
    try:
        # Get all listeners for the ALB
        listeners = elbv2.describe_listeners(LoadBalancerArn=alb_arn)['Listeners']
        
        for listener in listeners:
            # Get all rules for each listener
            rules = elbv2.describe_rules(ListenerArn=listener['ListenerArn'])['Rules']
            
            for rule in rules:
                for condition in rule.get('Conditions', []):
                    if condition['Field'] == 'host-header':
                        for value in condition['Values']:
                            # Check if domain matches or is a subdomain (wildcard)
                            if (value == domain_name or 
                                (value.startswith('*') and domain_name.endswith(value[1:]))):
                                return True
        return False
    
    except Exception as e:
        print(f"Error checking ALB rules: {e}")
        raise


def verify_a_record(alb_dns_name, domain_name):
    try:
        # Get ALB IPs
        alb_ips = set()
        alb_info = socket.getaddrinfo(alb_dns_name, None)
        for result in alb_info:
            alb_ips.add(result[4][0])  # Extract IPs

        # Get domain's resolved IPs
        domain_ips = set()
        domain_info = socket.getaddrinfo(domain_name, None)
        for result in domain_info:
            domain_ips.add(result[4][0])

        # Verify domain points to ALB
        if domain_ips.issubset(alb_ips):
            return 'done'
        else:
            return 'pending'

    except socket.gaierror as e:
        if "nodename nor servname provided" in str(e):
            return 'pending'
        else:
            return build_response(400, {'error': f'DNS resolution failed: {str(e)}'})
    except OSError as e:
        if "Device or resource busy" in str(e):
            return 'pending'
        else:
            return build_response(400, {'error': f'DNS resolution failed: {str(e)}'})

def request_certificate(domain_name):
    """Request an ACM certificate for the domain"""
    response = acm.request_certificate(
        DomainName=domain_name,
        ValidationMethod='DNS',
        Tags=[
            {
                'Key': 'AutoCreated',
                'Value': 'true'
            },
        ]
    )
    return response

def domain_alb_attachment(domain_name, https_listener_arn, target_group_arn, new_priority):
    """Request an ACM certificate for the domain"""
    response = elbv2.create_rule(
        ListenerArn=https_listener_arn,
        Priority=new_priority,
        Conditions=[
            {
                'Field': 'host-header',
                'HostHeaderConfig': {
                    'Values': [domain_name]
                }
            }
        ],
        Actions=[
            {
                'Type': 'forward',
                'TargetGroupArn': target_group_arn
            }
        ]
    )
    return response

def certificate_alb_attachment(https_listener_arn, certificate_arn):
    # 1. Add certificate to HTTPS listener
    response = elbv2.add_listener_certificates(
        ListenerArn=https_listener_arn,
        Certificates=[
            {
                'CertificateArn': certificate_arn
            }
        ]
    )
    return response

def certificate_exists_in_alb(alb_arn, certificate_arn):
    """
    Check if a certificate exists in any listener of an ALB
    """
    elbv2 = boto3.client('elbv2')
    
    try:
        # Get all listeners for the ALB
        listeners = elbv2.describe_listeners(LoadBalancerArn=alb_arn)['Listeners']
        
        for listener in listeners:
            # Check HTTPS listeners (port 443)
            if listener.get('Protocol') == 'HTTPS':
                # Check if certificate is in the default listener cert
                if listener.get('Certificates', []):
                    for cert in listener['Certificates']:
                        if cert['CertificateArn'] == certificate_arn:
                            return True
                
                # Check additional certificates (SNI)
                if listener.get('ExtraCertificates', []):
                    for cert in listener['ExtraCertificates']:
                        if cert['CertificateArn'] == certificate_arn:
                            return True
        return False
    
    except Exception as e:
        print(f"Error checking ALB listeners: {e}")
        raise    

def build_cors_preflight_response():
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'POST,OPTIONS',
            'Access-Control-Max-Age': '86400'
        },
        'body': ''
    }
            
def build_response(status_code, body):
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'POST,OPTIONS'
        },
        'body': json.dumps(body)
    }