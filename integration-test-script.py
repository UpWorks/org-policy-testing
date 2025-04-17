#!/usr/bin/env python3
"""
SCP Integration Test Example

This script demonstrates how to run the SCP test suite in a CI/CD pipeline
or as part of a manual validation process before deploying SCP changes.
"""

import os
import sys
import argparse
import logging
import json
import boto3
from datetime import datetime

# Import the test suite
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scp_test_suite import SCPServiceTest, SCPParityTest, SCPPolicyAnalysisTest, SCPValidationTest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scp_integration_test.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("scp_integration_test")

# Sample SCP to test
RESTRICTED_SERVICES_SCP = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyECSAccess",
            "Effect": "Deny",
            "Action": [
                "ecs:*"
            ],
            "Resource": "*"
        }
    ]
}

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run SCP integration tests')
    parser.add_argument('--policy-file', type=str, help='JSON file containing SCP policy to test')
    parser.add_argument('--target-ou', type=str, default='FTDEV', help='Target OU to test policy against')
    parser.add_argument('--apply', action='store_true', help='Apply the policy to the target OU')
    parser.add_argument('--rollback', action='store_true', help='Roll back policy changes after testing')
    parser.add_argument('--report-dir', type=str, default='reports', help='Directory for test reports')
    return parser.parse_args()

def load_policy_from_file(file_path):
    """Load an SCP policy from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading policy file: {str(e)}")
        raise

def create_test_policy(session, policy_content, name_prefix="TestPolicy"):
    """Create a test policy in AWS Organizations."""
    try:
        org_client = session.client('organizations')
        
        # Generate a unique policy name
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        policy_name = f"{name_prefix}-{timestamp}"
        
        # Create the policy
        response = org_client.create_policy(
            Content=json.dumps(policy_content),
            Description=f"Test policy created at {timestamp}",
            Name=policy_name,
            Type="SERVICE_CONTROL_POLICY"
        )
        
        logger.info(f"Created test policy: {policy_name} (ID: {response['Policy']['PolicySummary']['Id']})")
        return response['Policy']['PolicySummary']['Id']
    
    except Exception as e:
        logger.error(f"Error creating test policy: {str(e)}")
        raise

def attach_policy_to_ou(session, policy_id, ou_id):
    """Attach a policy to an organizational unit."""
    try:
        org_client = session.client('organizations')
        
        # Attach the policy
        org_client.attach_policy(
            PolicyId=policy_id,
            TargetId=ou_id
        )
        
        logger.info(f"Attached policy {policy_id} to OU {ou_id}")
        return True
    
    except Exception as e:
        logger.error(f"Error attaching policy to OU: {str(e)}")
        raise

def detach_policy_from_ou(session, policy_id, ou_id):
    """Detach a policy from an organizational unit."""
    try:
        org_client = session.client('organizations')
        
        # Detach the policy
        org_client.detach_policy(
            PolicyId=policy_id,
            TargetId=ou_id
        )
        
        logger.info(f"Detached policy {policy_id} from OU {ou_id}")
        return True
    
    except Exception as e:
        logger.error(f"Error detaching policy from OU: {str(e)}")
        raise

def delete_policy(session, policy_id):
    """Delete a policy from AWS Organizations."""
    try:
        org_client = session.client('organizations')
        
        # Delete the policy
        org_client.delete_policy(
            PolicyId=policy_id
        )
        
        logger.info(f"Deleted policy {policy_id}")
        return True
    
    except Exception as e:
        logger.error(f"Error deleting policy: {str(e)}")
        raise

def get_ou_id(session, ou_name):
    """Get the ID of an organizational unit by name."""
    try:
        org_client = session.client('organizations')
        
        # List roots
        roots = org_client.list_roots()
        
        # Start with the root
        parent_id = roots['Roots'][0]['Id']
        
        # List OUs under the root
        response = org_client.list_organizational_units_for_parent(ParentId=parent_id)
        
        # Find the OU with the matching name
        for ou in response['OrganizationalUnits']:
            if ou['Name'] == ou_name:
                logger.info(f"Found OU {ou_name} with ID {ou['Id']}")
                return ou['Id']
        
        # If we didn't find it at the root level, we could search deeper
        # (implementation omitted for brevity)
        
        logger.error(f"OU with name {ou_name} not found")
        return None
    
    except Exception as e:
        logger.error(f"Error getting OU ID: {str(e)}")
        raise

def run_tests():
    """Run the SCP test suite."""
    import unittest
    
    # Create a test suite with all the tests
    suite = unittest.TestSuite()
    
    # Add the test classes to the suite
    suite.addTest(unittest.makeSuite(SCPServiceTest))
    suite.addTest(unittest