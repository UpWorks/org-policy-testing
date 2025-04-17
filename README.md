# Sample AWS Org Policy Testing 

## Main Test Suite Components

### SCP Test Suite (Python): A full unittest-based framework that:

- Tests service permissions across OUs
- Verifies parity between DEV and USER OUs
- Analyzes SCP policies for structural correctness
- Generates detailed reports of test results

### Integration Test Script: A command-line tool that:

- Creates temporary test policies
- Applies them to specified OUs
- Runs the test suite against live AWS environments
- Generates reports and provides automatic rollback

### Sample SCP Configurations: JSON configuration for common SCPs that:

- Restrict S3 public access
- Protect RDS instances from deletion
- Limit root account usage
- Deny access to prohibited services like ECS
- Enforce MFA for sensitive operations

### Deployment Guide: Documentation that explains:

- The test workflow from development to production
- Best practices for SCP testing
- Troubleshooting common issues

## How to Use This Solution

The solution provides a structured approach to SCP testing that aligns with your requirement of rolling out changes to DEV first, then verifying them before applying to USER.

1. Create or modify SCPs using the provided examples as templates
2. Test in DEV using the integration script with --apply --rollback flags
3. Review test reports to verify functionality and check for permission gaps
4. Apply to USER once testing confirms proper functionality

## Next Steps

- Configure AWS Profiles: Set up profiles for both DEV and USER access
- Customize Test Actions: Add additional test actions specific to your workloads
- Integrate with Your Existing Tools: Consider adding to your workflow management

This solution addresses your core need of ensuring parity between OUs while allowing for safe testing of SCPs before broader deployment. The test suite also specifically checks for unauthorized service access like ECS, as mentioned in your requirements.


