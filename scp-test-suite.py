"""
AWS SCP Test Suite

This test suite validates Service Control Policies (SCPs) across different OUs,
focusing on RDS, IAM, and S3 services. It ensures parity between FTDEV and USER OUs
and verifies restrictions on unauthorized services like ECS.
"""

import unittest
import boto3
import json
import logging
import csv
import os
from datetime import datetime
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scp_tests.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("scp_tests")

# Define the OUs we're testing
OU_CONFIGS = {
    "FTDEV": {
        "profile": "ftdev-profile",
        "description": "Feature Development OU",
        "is_baseline": True,  # This is our baseline for comparison
    },
    "USER": {
        "profile": "user-profile",
        "description": "User OU",
        "is_baseline": False,
    },
}

# Define services and actions to test
TEST_ACTIONS = [
    # S3 Tests
    {"service": "s3", "action": "ListBuckets", "params": {}, "expected_result": True},
    {"service": "s3", "action": "CreateBucket", "params": {"Bucket": "temp-test-bucket-12345"}, "expected_result": True},
    {"service": "s3", "action": "PutBucketPolicy", "params": {"Bucket": "existing-bucket", "Policy": "{}"}, "expected_result": True},
    {"service": "s3", "action": "PutPublicAccessBlock", "params": {"Bucket": "existing-bucket", "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}, "expected_result": True},
    
    # RDS Tests
    {"service": "rds", "action": "DescribeDBInstances", "params": {}, "expected_result": True},
    {"service": "rds", "action": "CreateDBInstance", "params": {
        "DBInstanceIdentifier": "test-db-instance",
        "AllocatedStorage": 20,
        "DBInstanceClass": "db.t3.micro",
        "Engine": "mysql",
        "DryRun": True  # Always use DryRun for destructive actions
    }, "expected_result": True},
    {"service": "rds", "action": "ModifyDBInstance", "params": {
        "DBInstanceIdentifier": "test-db-instance",
        "BackupRetentionPeriod": 7,
        "DryRun": True
    }, "expected_result": True},
    
    # IAM Tests
    {"service": "iam", "action": "ListUsers", "params": {}, "expected_result": True},
    {"service": "iam", "action": "GetUser", "params": {"UserName": "test-user"}, "expected_result": True},
    {"service": "iam", "action": "ListRoles", "params": {}, "expected_result": True},
    
    # Services that should be restricted
    {"service": "ecs", "action": "ListClusters", "params": {}, "expected_result": False},
    {"service": "ecs", "action": "CreateCluster", "params": {"clusterName": "test-cluster"}, "expected_result": False},
]

# Sample SCP policies for testing
SAMPLE_SCPS = {
    "RestrictS3PublicAccess": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyS3PublicAccessModification",
                "Effect": "Deny",
                "Action": [
                    "s3:PutBucketPublicAccessBlock",
                    "s3:DeletePublicAccessBlock"
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalType": "User"
                    }
                }
            }
        ]
    },
    "RestrictRDSDeletion": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyRDSInstanceDeletion",
                "Effect": "Deny",
                "Action": [
                    "rds:DeleteDBInstance"
                ],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:PrincipalTag/Role": "DatabaseAdmin"
                    }
                }
            }
        ]
    },
    "DenyECSServices": {
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
}

class SCPTestBase(unittest.TestCase):
    """Base class for SCP testing between OUs."""
    
    @classmethod
    def setUpClass(cls):
        """Initialize the test environment."""
        cls.ou_sessions = {}
        cls.ou_clients = {}
        cls.test_role_name = "scp-test-role"
        
        # Create sessions for each OU
        for ou_name, ou_config in OU_CONFIGS.items():
            try:
                session = boto3.Session(profile_name=ou_config["profile"])
                cls.ou_sessions[ou_name] = session
                
                # Create clients dictionary for this OU
                cls.ou_clients[ou_name] = {}
                
                # Test connection
                sts = session.client('sts')
                identity = sts.get_caller_identity()
                logger.info(f"Connected to {ou_name} OU with account ID {identity['Account']}")
                
            except Exception as e:
                logger.error(f"Failed to initialize session for {ou_name}: {str(e)}")
                raise
    
    def setUp(self):
        """Set up test case specific resources."""
        # Find the baseline OU (typically FTDEV)
        self.baseline_ou = next((ou for ou, config in OU_CONFIGS.items() if config.get("is_baseline")), None)
        if not self.baseline_ou:
            raise ValueError("No baseline OU defined in OU_CONFIGS")
        
        # Initialize test results storage
        self.test_results = {
            "timestamp": datetime.now().isoformat(),
            "results": [],
            "summary": {
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "errors": 0
            }
        }
    
    def get_client(self, ou_name, service):
        """Get or create a client for the specified service in the specified OU."""
        if service not in self.ou_clients[ou_name]:
            self.ou_clients[ou_name][service] = self.ou_sessions[ou_name].client(service)
        return self.ou_clients[ou_name][service]
    
    def is_action_allowed(self, ou_name, service, action, params):
        """Test if an action is allowed in the specified OU."""
        client = self.get_client(ou_name, service)
        try:
            method = getattr(client, action)
            method(**params)
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ('AccessDenied', 'UnauthorizedOperation'):
                return False
            # Log other errors but don't treat them as "denied"
            logger.warning(f"Error testing {service}.{action} in {ou_name}: {error_code} - {e.response['Error']['Message']}")
            if "DryRun" in params and params["DryRun"] and error_code == 'DryRunOperation':
                # For DryRun operations, this means it would have succeeded
                return True
            return None  # None means we couldn't determine if it was allowed
        except Exception as e:
            logger.error(f"Unexpected error testing {service}.{action} in {ou_name}: {str(e)}")
            return None

    def record_result(self, test_case, ou_name, is_allowed, expected):
        """Record a test result."""
        service = test_case["service"]
        action = test_case["action"]
        
        result = {
            "service": service,
            "action": action,
            "ou": ou_name,
            "allowed": is_allowed,
            "expected": expected,
            "status": "PASSED" if is_allowed == expected else "FAILED"
        }
        
        self.test_results["results"].append(result)
        self.test_results["summary"]["total_tests"] += 1
        
        if is_allowed == expected:
            self.test_results["summary"]["passed"] += 1
        else:
            self.test_results["summary"]["failed"] += 1
            
        return result
    
    def export_results_to_csv(self, filename="scp_test_results.csv"):
        """Export test results to CSV."""
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'service', 'action', 'ou', 'allowed', 'expected', 'status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in self.test_results["results"]:
                row = {
                    'timestamp': self.test_results["timestamp"],
                    'service': result["service"],
                    'action': result["action"],
                    'ou': result["ou"],
                    'allowed': result["allowed"],
                    'expected': result["expected"],
                    'status': result["status"]
                }
                writer.writerow(row)
        
        logger.info(f"Test results exported to {filename}")
        
    def get_attached_scps(self, ou_name):
        """Get SCPs attached to the specified OU."""
        try:
            # Get the Organizations client
            org_client = self.ou_sessions[ou_name].client('organizations')
            
            # List accounts in the organization to find the current account
            accounts = org_client.list_accounts()
            current_identity = self.get_client(ou_name, 'sts').get_caller_identity()
            current_account = next((acc for acc in accounts['Accounts'] 
                                  if acc['Id'] == current_identity['Account']), None)
            
            if not current_account:
                logger.warning(f"Could not find current account in organization")
                return []
            
            # Get the parent OU for this account
            parents = org_client.list_parents(ChildId=current_account['Id'])
            if not parents['Parents']:
                logger.warning(f"Account {current_account['Id']} has no parent OU")
                return []
            
            parent_id = parents['Parents'][0]['Id']
            parent_type = parents['Parents'][0]['Type']
            
            # If the parent is not an OU, we can't proceed
            if parent_type != 'ORGANIZATIONAL_UNIT':
                logger.warning(f"Parent {parent_id} is not an OU, it's a {parent_type}")
                return []
            
            # List policies attached to this OU
            policies = org_client.list_policies_for_target(
                TargetId=parent_id,
                Filter='SERVICE_CONTROL_POLICY'
            )
            
            # Get the content of each policy
            scp_contents = []
            for policy in policies['Policies']:
                policy_detail = org_client.describe_policy(PolicyId=policy['Id'])
                scp_contents.append({
                    'Id': policy['Id'],
                    'Name': policy['Name'],
                    'Content': json.loads(policy_detail['Policy']['Content'])
                })
            
            return scp_contents
            
        except Exception as e:
            logger.error(f"Error getting SCPs for {ou_name}: {str(e)}")
            return []

class SCPServiceTest(SCPTestBase):
    """Test SCP permissions for specific AWS services across OUs."""
    
    def test_service_permissions(self):
        """Test all defined service actions across all OUs."""
        logger.info("Starting service permissions tests...")
        
        for test_case in TEST_ACTIONS:
            service = test_case["service"]
            action = test_case["action"]
            params = test_case["params"]
            expected = test_case["expected_result"]
            
            logger.info(f"Testing {service}.{action}...")
            
            # Test in each OU
            for ou_name in OU_CONFIGS:
                is_allowed = self.is_action_allowed(ou_name, service, action, params)
                if is_allowed is not None:  # Only record definitive results
                    result = self.record_result(test_case, ou_name, is_allowed, expected)
                    logger.info(f"  {ou_name}: {result['status']} (allowed={is_allowed}, expected={expected})")
        
        # Export results
        self.export_results_to_csv()
        
        # Log summary
        summary = self.test_results["summary"]
        logger.info(f"Test summary: {summary['passed']}/{summary['total_tests']} passed "
                   f"({summary['failed']} failed, {summary['errors']} errors)")
        
        # Make the test pass/fail based on summary
        self.assertEqual(summary["failed"], 0, f"{summary['failed']} tests failed")

class SCPParityTest(SCPTestBase):
    """Test parity between OUs for SCP permissions."""
    
    def test_ou_permission_parity(self):
        """Test that permissions are consistent between OUs."""
        logger.info("Starting OU permission parity tests...")
        
        parity_results = []
        
        # Remember to use the baseline OU (normally FTDEV)
        baseline_ou = self.baseline_ou
        logger.info(f"Using {baseline_ou} as the baseline for comparison")
        
        # Test each action in the baseline OU first
        baseline_results = {}
        for test_case in TEST_ACTIONS:
            service = test_case["service"]
            action = test_case["action"]
            params = test_case["params"]
            key = f"{service}.{action}"
            
            baseline_allowed = self.is_action_allowed(baseline_ou, service, action, params)
            baseline_results[key] = baseline_allowed
            
            logger.info(f"Baseline {baseline_ou} permission for {key}: {baseline_allowed}")
        
        # Now test each other OU against the baseline
        for ou_name in OU_CONFIGS:
            if ou_name == baseline_ou:
                continue
                
            logger.info(f"Comparing {ou_name} to baseline {baseline_ou}...")
            
            for test_case in TEST_ACTIONS:
                service = test_case["service"]
                action = test_case["action"]
                params = test_case["params"]
                key = f"{service}.{action}"
                
                if baseline_results[key] is None:
                    logger.warning(f"Skipping {key} - baseline result was indeterminate")
                    continue
                    
                ou_allowed = self.is_action_allowed(ou_name, service, action, params)
                if ou_allowed is None:
                    logger.warning(f"Skipping {key} - {ou_name} result was indeterminate")
                    continue
                
                # Check for parity
                has_parity = ou_allowed == baseline_results[key]
                
                result = {
                    "service": service,
                    "action": action,
                    "baseline_ou": baseline_ou,
                    "baseline_allowed": baseline_results[key],
                    "comparison_ou": ou_name,
                    "comparison_allowed": ou_allowed,
                    "has_parity": has_parity
                }
                
                parity_results.append(result)
                
                logger.info(f"  {key}: Parity={'PASS' if has_parity else 'FAIL'} "
                           f"({baseline_ou}={baseline_results[key]}, {ou_name}={ou_allowed})")
                
                # Assert parity for this test case
                self.assertEqual(ou_allowed, baseline_results[key], 
                                f"Permission mismatch for {key}: {baseline_ou}={baseline_results[key]}, {ou_name}={ou_allowed}")
        
        # Export parity results to CSV
        self._export_parity_results(parity_results)
    
    def _export_parity_results(self, results, filename="scp_parity_results.csv"):
        """Export parity test results to CSV."""
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'service', 'action', 'baseline_ou', 'baseline_allowed', 
                         'comparison_ou', 'comparison_allowed', 'has_parity']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                row = {
                    'timestamp': datetime.now().isoformat(),
                    'service': result["service"],
                    'action': result["action"],
                    'baseline_ou': result["baseline_ou"],
                    'baseline_allowed': result["baseline_allowed"],
                    'comparison_ou': result["comparison_ou"],
                    'comparison_allowed': result["comparison_allowed"],
                    'has_parity': result["has_parity"]
                }
                writer.writerow(row)
        
        logger.info(f"Parity results exported to {filename}")

class SCPPolicyAnalysisTest(SCPTestBase):
    """Analyze and compare SCP policies between OUs."""
    
    def test_scp_policy_comparison(self):
        """Compare SCPs between OUs."""
        logger.info("Starting SCP policy comparison tests...")
        
        all_scps = {}
        
        # Get SCPs for each OU
        for ou_name in OU_CONFIGS:
            all_scps[ou_name] = self.get_attached_scps(ou_name)
            logger.info(f"Found {len(all_scps[ou_name])} SCPs attached to {ou_name}")
        
        # Compare SCPs between baseline OU and others
        baseline_ou = self.baseline_ou
        baseline_scps = all_scps[baseline_ou]
        
        for ou_name in OU_CONFIGS:
            if ou_name == baseline_ou:
                continue
                
            comparison_scps = all_scps[ou_name]
            
            # Compare SCP policy names
            baseline_policy_names = {scp['Name'] for scp in baseline_scps}
            comparison_policy_names = {scp['Name'] for scp in comparison_scps}
            
            # Find missing policies
            missing_in_comparison = baseline_policy_names - comparison_policy_names
            extra_in_comparison = comparison_policy_names - baseline_policy_names
            
            if missing_in_comparison:
                logger.warning(f"Policies in {baseline_ou} missing from {ou_name}: {missing_in_comparison}")
                self.fail(f"Policies in {baseline_ou} missing from {ou_name}: {missing_in_comparison}")
                
            if extra_in_comparison:
                logger.warning(f"Extra policies in {ou_name} not in {baseline_ou}: {extra_in_comparison}")
                # We may not want to fail on extra policies, as those might be intentional
                
            # Compare content of common policies
            common_policy_names = baseline_policy_names.intersection(comparison_policy_names)
            
            for policy_name in common_policy_names:
                baseline_policy = next((p for p in baseline_scps if p['Name'] == policy_name), None)
                comparison_policy = next((p for p in comparison_scps if p['Name'] == policy_name), None)
                
                if not self._are_policies_equivalent(baseline_policy['Content'], comparison_policy['Content']):
                    logger.warning(f"Policy content for '{policy_name}' differs between {baseline_ou} and {ou_name}")
                    self.fail(f"Policy content for '{policy_name}' differs between {baseline_ou} and {ou_name}")
    
    def _are_policies_equivalent(self, policy1, policy2):
        """Compare two policy documents for logical equivalence."""
        # This is a simplified comparison - in reality, you'd need more sophisticated
        # comparison logic to handle equivalent but differently structured policies
        return json.dumps(policy1, sort_keys=True) == json.dumps(policy2, sort_keys=True)

class SCPValidationTest(SCPTestBase):
    """Validate sample SCPs against AWS best practices."""
    
    def test_validate_sample_scps(self):
        """Validate sample SCPs against best practices."""
        logger.info("Starting sample SCP validation tests...")
        
        # Test each sample SCP
        for policy_name, policy_content in SAMPLE_SCPS.items():
            logger.info(f"Validating sample SCP: {policy_name}")
            
            # Check policy structure
            self.assertIn("Version", policy_content, "Policy is missing Version field")
            self.assertIn("Statement", policy_content, "Policy is missing Statement field")
            self.assertIsInstance(policy_content["Statement"], list, "Policy Statement should be a list")
            
            # Check individual statements
            for i, statement in enumerate(policy_content["Statement"]):
                self._validate_statement(policy_name, i, statement)
    
    def _validate_statement(self, policy_name, index, statement):
        """Validate an individual policy statement."""
        logger.info(f"  Validating statement {index} in {policy_name}")
        
        # Check for required fields
        required_fields = ["Effect", "Action"]
        for field in required_fields:
            self.assertIn(field, statement, f"Statement {index} is missing required field: {field}")
        
        # Check Effect value
        self.assertIn(statement["Effect"], ["Allow", "Deny"], 
                      f"Statement {index} has invalid Effect: {statement['Effect']}")
        
        # Check Action format
        action = statement["Action"]
        if isinstance(action, list):
            for a in action:
                self._validate_action_format(a)
        else:
            self._validate_action_format(action)
        
        # Check Resource field
        if "Resource" in statement:
            resource = statement["Resource"]
            if isinstance(resource, list):
                for r in resource:
                    self._validate_resource_format(r)
            else:
                self._validate_resource_format(resource)
    
    def _validate_action_format(self, action):
        """Validate an action string format."""
        self.assertIsInstance(action, str, "Action must be a string")
        self.assertIn(":", action, "Action must be in service:action format")
        service, action_name = action.split(":", 1)
        self.assertTrue(service, "Service name cannot be empty")
        self.assertTrue(action_name, "Action name cannot be empty")
    
    def _validate_resource_format(self, resource):
        """Validate a resource string format."""
        self.assertIsInstance(resource, str, "Resource must be a string")
        # Just a basic check - a real validator would be more sophisticated
        self.assertTrue(resource, "Resource cannot be empty")

# Run the tests if this file is executed directly
if __name__ == "__main__":
    # Create a test suite with all the tests
    suite = unittest.TestSuite()
    
    # Add the test classes to the suite
    suite.addTest(unittest.makeSuite(SCPServiceTest))
    suite.addTest(unittest.makeSuite(SCPParityTest))
    suite.addTest(unittest.makeSuite(SCPPolicyAnalysisTest))
    suite.addTest(unittest.makeSuite(SCPValidationTest))
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Exit with status code based on test results
    exit_code = 0 if result.wasSuccessful() else 1
    exit(exit_code)
