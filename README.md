# AWS_security_specialty


2024/12/14

<img width="1442" alt="image" src="https://github.com/user-attachments/assets/7492c146-e39e-4c01-9eb1-7d64d65b91bb" />
B. AWS Config for Configuration Tracking
Functionality: AWS Config continuously monitors and records the configurations of your AWS resources. It provides a history of configuration changes and evaluates resource configurations against desired compliance rules.
Advantages:
State-Based Monitoring: Directly records the current state of resources, ensuring that only the latest configuration is considered.
Compliance Evaluation: Integrates seamlessly with AWS Config Rules to automatically assess compliance.
Operational Efficiency: Minimal manual intervention required once set up. AWS Config handles the aggregation and state management inherently.
Visualization and History: Provides a clear view of resource states over time, making it easier to track compliance and changes.


Why Option B is the Best Choice:
Comprehensive Configuration Tracking: AWS Config is purpose-built to track, record, and evaluate the configurations of AWS resources.
Handles Rapid Changes Gracefully: It inherently captures the latest state of resources, ensuring that even if multiple changes occur in quick succession, only the final configuration is considered.
Automated Compliance Evaluation: With AWS Config Rules, you can define compliance standards that are automatically evaluated against the current resource states.
Operational Efficiency: Once set up, AWS Config requires minimal maintenance, providing continuous and automated monitoring without the need for manual processing or intervention.


<img width="1434" alt="image" src="https://github.com/user-attachments/assets/44d164c5-33c2-4555-a345-dcb9e6abd7c1" />

To troubleshoot the issue where AWS CloudFormation stack updates fail in the Production OU due to insufficient IAM permissions, the FIRST step should be to identify the exact cause of the permission failure. This involves understanding which specific API calls are being denied and why they are failing.

Recommended Action:
A. Review the AWS CloudTrail logs in the account in the Production OU. Search for any failed API calls from CloudFormation during the deployment attempt.

Why Option A is the Best Choice:
Direct Insight into Failures:

AWS CloudTrail logs all API calls made within your AWS account, including those initiated by AWS CloudFormation.
By reviewing CloudTrail logs, you can pinpoint exactly which API calls are failing and the specific reasons for their failure.
Identify Policy Constraints:

The error message indicates insufficient IAM permissions, which could be due to:
Service Control Policies (SCPs) attached to the Production OU that restrict certain actions.
IAM policies attached to the roles used by CloudFormation.
CloudTrail logs will show whether the failures are due to explicit denies from SCPs or missing permissions in IAM policies.
Operational Efficiency:

Non-Invasive: Reviewing logs does not alter any existing configurations or policies, ensuring that your production environment remains stable during troubleshooting.
Focused Investigation: Allows you to focus on the specific permissions that are causing the issue, rather than broadly modifying policies which could have unintended consequences.
Compliance and Auditing:

CloudTrail provides a historical record of actions, which is valuable for auditing and compliance purposes.
Understanding the sequence of events leading to the failure helps in maintaining a secure and compliant infrastructure.


<img width="1435" alt="image" src="https://github.com/user-attachments/assets/d64d09c7-d330-463a-86e3-a763dad546da" />
C. Use the DynamoDB Encryption Client. Use client-side encryption. Sign the table items.
Pros:
End-to-End Encryption: The DynamoDB Encryption Client performs encryption on the client side before data is sent to DynamoDB, ensuring data is encrypted both in transit and at rest.
Data Integrity: By signing the table items, it allows detection of unauthorized data changes, maintaining data integrity.
Operational Efficiency: Specifically designed for DynamoDB, simplifying integration and management.

Why Option C is the Best Choice:
Tailored for DynamoDB: The DynamoDB Encryption Client is specifically designed to integrate seamlessly with DynamoDB, providing straightforward implementation for client-side encryption and data signing.

Comprehensive Protection:

Encryption at Rest and In Transit: Ensures data is secure both while stored in DynamoDB and during transmission.
Data Integrity: Signing the table items allows the detection of any unauthorized modifications, ensuring that data has not been tampered with.
Operational Efficiency: As a specialized tool, it reduces the complexity associated with setting up and managing encryption and integrity checks, allowing for easier maintenance and scalability.

Implementation Steps:
Integrate DynamoDB Encryption Client:

Incorporate the DynamoDB Encryption Client library into your application code.
Configure the client with appropriate encryption settings and AWS KMS keys.
Encrypt Data Before Storage:

Ensure that all data written to DynamoDB is encrypted client-side using the Encryption Client.
Sign Table Items:

Enable data signing within the Encryption Client to ensure that each item can be verified for integrity upon retrieval.
Monitor and Verify Integrity:

Implement mechanisms to verify the signatures of retrieved data, allowing detection of any unauthorized changes.





<img width="1444" alt="image" src="https://github.com/user-attachments/assets/a68fd69d-85e0-4b9a-8a88-ba2350485421" />

Why Option D is the Most Suitable
Real-Time Detection and Remediation:

Amazon EventBridge allows real-time detection of the creation of RDS DB instances or clusters. This ensures immediate action when an unencrypted resource is created.
The direct invocation of an AWS Lambda function streamlines the remediation process without involving intermediate steps.
Operational Simplicity and Efficiency:

By directly invoking the Lambda function, the solution minimizes complexity compared to using SNS for intermediate communication (as in Option C).
The Lambda function performs both tasks: sending an email alert via Amazon SNS and terminating the unencrypted resource, combining multiple actions in a single step.
Automated Termination and Alerting:

The Lambda function automatically terminates the non-compliant resource, ensuring compliance without manual intervention.
It also publishes a notification to an SNS topic for email alerts, keeping stakeholders informed.





<img width="744" alt="image" src="https://github.com/user-attachments/assets/d5e5040a-e917-4437-920a-86424aec86c7" />
<img width="803" alt="image" src="https://github.com/user-attachments/assets/55183e60-9095-4aec-8f8d-d06c1d8343c6" />
<img width="638" alt="image" src="https://github.com/user-attachments/assets/31ab8af3-1e66-4a65-a88a-4c8878d8f7f1" />
<img width="711" alt="image" src="https://github.com/user-attachments/assets/582d4b7b-1f44-494d-a28f-1e1650eda261" />


<img width="736" alt="image" src="https://github.com/user-attachments/assets/4bfd408b-95da-4311-8568-aac77e9d4ee6" />
Recommended Solution:
D. Use SCPs to deny all lambda:CreateFunctionUrlConfig and lambda:UpdateFunctionUrlConfig actions that have a lambda:FunctionUrlAuthType condition key value of NONE.

Implementation Steps:
Create an SCP: Define an SCP that specifically denies the lambda:CreateFunctionUrlConfig and lambda:UpdateFunctionUrlConfig actions when the lambda:FunctionUrlAuthType is set to NONE.

json
Copy code
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "lambda:CreateFunctionUrlConfig",
        "lambda:UpdateFunctionUrlConfig"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "lambda:FunctionUrlAuthType": "NONE"
        }
      }
    }
  ]
}
Attach the SCP to Production OU: Apply this SCP to the Organizational Unit (OU) that contains all production accounts. This ensures that the policy is enforced across all relevant accounts.

Verify Enforcement: Test the policy by attempting to create or update a Lambda function URL with AuthType set to NONE in a production account. The action should be denied.

Benefits of This Approach:
Centralized Control: Manage policies from a single point within AWS Organizations.
Automated Enforcement: Prevents unauthenticated function URLs without requiring developers to make changes.
Scalable: Easily applies to hundreds of accounts under the organizational structure.
Security Compliance: Ensures that production environments adhere to security best practices by enforcing authenticated access.
Conclusion:
Option D provides a robust, scalable, and low-overhead solution to prevent unauthenticated Lambda function URLs in production environments by leveraging SCPs within AWS Organizations.






2024/12/13

<img width="1453" alt="image" src="https://github.com/user-attachments/assets/cf0a5322-03a9-4edd-b4ac-910250a4d2c8">

<img width="1130" alt="image" src="https://github.com/user-attachments/assets/f7695195-7651-40ef-a454-2af126cc2321">
Answer: B. Configure AWS Verified Access. Add the application by creating an endpoint for the ALB.

Explanation:
To provide secure access to the application without requiring a VPN and ensure that users meet specific security conditions, including a defined device posture, AWS Verified Access is the most suitable solution. Here's why:

Zero Trust Network Access (ZTNA):

AWS Verified Access implements a Zero Trust security model, which ensures that access is granted based on the verification of user identity and device posture rather than assuming trust based on network location.
This approach aligns with the requirement to provide secure access without the need for a traditional VPN.
Device Posture Assessment:

AWS Verified Access can evaluate the security posture of devices attempting to access the application. This includes checking for compliance with security policies such as antivirus status, patch levels, and other security configurations.
By enforcing these conditions, only devices that meet the defined security criteria can access the application, ensuring that sensitive inventory data remains protected.
Integration with Application Load Balancer (ALB):

By creating an endpoint for the ALB within AWS Verified Access, you can seamlessly integrate the access control mechanisms with your existing application infrastructure.
This integration allows for centralized management of access policies and simplifies the enforcement of security conditions across all users and devices.
Operational Efficiency:

AWS Verified Access is a managed service that reduces the operational overhead associated with setting up and maintaining secure access mechanisms.
It eliminates the need for deploying and managing VPN infrastructure, making the solution more efficient and easier to maintain, especially when dealing with hundreds of vendors.



<img width="748" alt="image" src="https://github.com/user-attachments/assets/bf47178e-c167-46d4-9a66-5d1cc0bfd8ad">
Explanation:
To prevent Amazon S3 objects from being shared with IAM identities outside of the company’s AWS Organization, the most effective and operationally efficient approach involves using Service Control Policies (SCPs) with conditions based on the organization ID. Here's how this can be achieved:

Understanding SCPs and Condition Keys:

Service Control Policies (SCPs): SCPs are policies applied at the AWS Organizations level to manage permissions across all accounts within the organization. They act as a permission boundary, ensuring that accounts cannot perform actions outside the allowed policies.
Condition Keys: AWS provides specific condition keys to tailor SCPs based on organizational attributes. For this scenario, the relevant condition key is aws:PrincipalOrgID.
Using aws:PrincipalOrgID:

Purpose: The aws:PrincipalOrgID condition key allows you to specify the organization ID of the principal making the request. By leveraging this key, you can ensure that only principals (users, roles, etc.) within your organization are permitted to perform certain actions.
Implementation: By denying S3 actions (s3:*) when the aws:PrincipalOrgID does not match your organization's ID, you effectively prevent any IAM identities outside your organization from accessing S3 objects.
Constructing the SCP:

Effect: Deny
Action: s3:* (all S3 actions)
Condition: StringNotEquals on aws:PrincipalOrgID with the value set to your organization's ID.
Example SCP Structure:

json
Copy code
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyS3AccessOutsideOrg",
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {
                    "aws:PrincipalOrgID": "o-xxxxxxxxxx"
                }
            }
        }
    ]
}
Operational Efficiency:

Scalability: This approach scales seamlessly as it doesn't require listing individual external IAM principals. Any new external IAM identities are automatically denied unless they are part of the organization.
Maintenance: Since the condition is based on the organization ID, there's minimal ongoing maintenance required, even if the vendor list changes weekly. There's no need to programmatically add or remove principals from the policy.
Ensuring Correct Implementation:

Correct Condition Key: It's crucial to use aws:PrincipalOrgID instead of aws:ResourceOrgID. The former checks the organization ID of the principal making the request, which aligns with the requirement to restrict access based on the organization.
Policy Attachment: Ensure that the SCP is attached at the appropriate level in AWS Organizations (e.g., root or specific organizational units) to cover all relevant accounts.




<img width="1420" alt="image" src="https://github.com/user-attachments/assets/c7f20046-f499-4c41-a370-8b896e5d7d37">


Thought for 23 seconds
Answer: A. Review the SAML IdP logs to identify errors. Check AWS CloudTrail to verify the API calls that the user made.

Explanation:
When a federated user experiences an authentication failure in a setup using SAML 2.0 with AWS IAM Identity Center (formerly AWS Single Sign-On) and IAM roles, the issue typically lies in either the identity provider (IdP) configuration or the AWS side (such as IAM roles and permissions). To troubleshoot this effectively and efficiently, follow these steps:

Review SAML IdP Logs:

Purpose: The SAML IdP logs provide detailed information about the authentication attempts made by users. By examining these logs, you can identify if the authentication request reached the IdP, whether it was processed successfully, or if there were any errors in generating the SAML assertion.
Action: Access the logs from your SAML IdP (in this case, AWS IAM Identity Center) to check for any error messages or failed authentication attempts related to the user experiencing issues.
Check AWS CloudTrail Logs:

Purpose: AWS CloudTrail logs record all API calls made in your AWS account, including those related to authentication and role assumption. By examining these logs, you can determine if the user's authentication request was received by AWS, whether the role assumption was attempted, and if any errors occurred during this process.
Action:
Navigate to the CloudTrail console.
Search for events related to the user's authentication attempt, such as AssumeRoleWithSAML.
Analyze the events to identify any error codes or messages that indicate why the authentication failed (e.g., invalid SAML assertion, role not found, permissions issues).
Why Option A is the Best Choice:
Comprehensive Troubleshooting: By combining insights from both the IdP logs and CloudTrail, you get a full picture of the authentication flow—from the initial request at the IdP to the role assumption attempt in AWS.

Operational Efficiency: This approach leverages existing logging mechanisms without requiring additional tools or configurations. It allows for quick identification of where the failure is occurring, whether it's on the IdP side or within AWS.

<img width="1430" alt="image" src="https://github.com/user-attachments/assets/c42603ba-a99c-42af-a108-eb3cebe8b01f">


Explanation:
To prevent any modifications to the data in the Amazon S3 bucket, the most effective and robust solution is to use S3 Object Lock in compliance mode with S3 bucket versioning enabled. Here's why this approach meets the requirements:

1. S3 Object Lock in Compliance Mode:
Immutability: S3 Object Lock provides a way to enforce write-once-read-many (WORM) semantics for S3 objects. When Object Lock is configured in compliance mode, it ensures that data cannot be deleted or overwritten for a specified retention period.

Strict Enforcement: In compliance mode, even users with administrative privileges (including the root user) cannot alter or delete the locked objects until the retention period expires. This ensures that the data remains unmodifiable, aligning perfectly with the requirement to prevent any modifications.

Regulatory Compliance: Compliance mode is designed to meet regulatory requirements where data immutability is mandatory. It provides an additional layer of protection against both accidental and malicious modifications.

2. Enabling S3 Bucket Versioning:
Version Control: Enabling versioning on the S3 bucket ensures that all versions of an object are preserved. This is crucial for maintaining a complete history of data changes, which complements the immutability enforced by Object Lock.

Protection Against Overwrites: With versioning enabled, even if someone attempts to overwrite an object, previous versions remain intact and protected by Object Lock. This adds another layer of security, ensuring that no data loss occurs.





<img width="896" alt="image" src="https://github.com/user-attachments/assets/1ec50176-757e-436d-8ebc-9c96ad0b5a10">
Explanation:
To prevent IAM principals outside of your AWS Organization from accessing your Amazon S3 buckets while ensuring that existing access within the Organizational Units (OUs) remains unaffected, the most effective solution involves using Service Control Policies (SCPs) with appropriate conditions based on organizational attributes.

1. Understanding Service Control Policies (SCPs):
SCPs are policies applied at the AWS Organizations level that define the maximum available permissions for member accounts within the organization. They act as permission boundaries, ensuring that accounts cannot perform actions outside the scope defined by the SCPs.
2. Leveraging Condition Keys for Organizational Boundaries:
Condition Keys: AWS provides specific condition keys to enforce policies based on organizational attributes. In this scenario, the relevant condition keys are:
aws:PrincipalOrgID: Identifies the AWS Organization ID of the IAM principal making the request.
aws:ResourceOrgID: Identifies the AWS Organization ID of the resource being accessed.
3. Implementing the SCP:
Objective: Deny all s3:* actions for principals that do not belong to the organization's AWS Organization.

Policy Structure:

json
Copy code
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyS3AccessOutsideOrg",
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {
                    "aws:PrincipalOrgID": "o-xxxxxxxxxx"  // Replace with your Organization ID
                }
            }
        }
    ]
}
Effect: Denies all S3 actions (s3:*).
Condition: The denial is triggered when the principal's organization ID (aws:PrincipalOrgID) does not match the company's organization ID (o-xxxxxxxxxx).
4. Ensuring Existing Access Remains Unaffected:
Exclusion of Internal OUs: Since the SCP is scoped based on the aws:PrincipalOrgID, it inherently allows access for IAM principals within the organization’s OUs. Only external principals (those outside the specified organization ID) will be denied access.

No Impact on Internal Access: Existing access permissions within the OUs remain intact because the condition specifically targets principals not part of the organization.

5. Operational Efficiency:
Scalability: This approach scales seamlessly as new OUs are added or removed within the organization without needing to update the SCP for each OU.

Maintenance: Minimal maintenance is required since the policy centrally manages access based on organizational boundaries rather than individual account or user configurations.


<img width="1422" alt="image" src="https://github.com/user-attachments/assets/d80261c1-33c4-4889-b4bf-d8c95bc0e163">

Explanation:
To prevent Amazon Inspector alerts from being sent to the application while allowing other Security Hub findings, the security engineer should adjust the Amazon EventBridge rule to exclude events originating from Amazon Inspector. This approach ensures that only relevant findings trigger the Lambda function, thereby reducing unnecessary alerts and maintaining operational efficiency.

Why Option C is the Best Choice:
Event Filtering at the Source:

EventBridge Rules: By modifying the EventBridge rule to exclude events based on the ProductArn, you ensure that only desired findings (excluding those from Amazon Inspector) are processed.
Condition Element: Using the anything-but operator with the ProductArn condition effectively filters out all events from Amazon Inspector, ensuring they do not trigger the Lambda function.
Operational Efficiency:

Minimal Changes: Adjusting the EventBridge rule requires a simple configuration change without altering existing infrastructure or adding new components.
No Code Modifications: There's no need to update the Lambda function's code, which avoids potential bugs and reduces deployment overhead.
Scalability and Maintenance:

Centralized Control: Managing exclusions directly within EventBridge rules provides a centralized and scalable method to control which findings are processed.
Ease of Updates: If additional services need to be excluded in the future, they can be easily added to the EventBridge rule without significant architectural changes.
Implementation Steps for Option C:
Navigate to Amazon EventBridge:

Open the Amazon EventBridge console in the us-west-2 region.
Locate the Relevant Rule:

Find the rule that captures Security Hub findings and targets the Lambda function.
Modify the Event Pattern:

Edit the event pattern to include a condition that excludes events from Amazon Inspector.
Example Event Pattern Modification:
json
Copy code
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"],
  "detail": {
    "ProductArn": [{
      "anything-but": "arn:aws:securityhub:us-west-2::product/aws/inspector"
    }]
  }
}
This pattern ensures that any findings from Amazon Inspector (arn:aws:securityhub:us-west-2::product/aws/inspector) are excluded from triggering the Lambda function.
Save and Test the Rule:

Save the updated rule and monitor to ensure that only non-Inspector findings are sent to the application’s channel.





<img width="1449" alt="image" src="https://github.com/user-attachments/assets/04565fb4-374d-4d32-b747-83138cf46be2">
Explanation:
To enable logging of AWS Lambda function output to Amazon CloudWatch Logs, it's essential to ensure that the Lambda function has the appropriate execution role with the necessary permissions and that the role's trust policy allows the Lambda service to assume it. Here's a detailed breakdown of why Options A and B are the correct choices:

1. Option A: Verify the Trust Policy of the Execution Role
Statement:

Check the role that is defined in the CloudFormation template and is passed to the Lambda function. Ensure that the role has a trust policy that allows the sts:AssumeRole action by the service principal lambda.amazonaws.com.

Reasoning:

Role Assumption by Lambda: The Lambda service (lambda.amazonaws.com) must be allowed to assume the execution role. This is defined in the role's trust policy.

Trust Policy Configuration: If the trust policy does not permit lambda.amazonaws.com to assume the role, the Lambda function will not be able to execute with the intended permissions, including writing logs to CloudWatch Logs.

Operational Efficiency: Ensuring the trust policy is correctly configured is a foundational step that prevents the Lambda function from running entirely, thereby avoiding further issues related to permissions.

Implementation Steps:

Review the CloudFormation Template:
Locate the IAM role resource associated with the Lambda function.
Check the Trust Policy:
Ensure it includes the following statement:
json
Copy code
{
  "Effect": "Allow",
  "Principal": {
    "Service": "lambda.amazonaws.com"
  },
  "Action": "sts:AssumeRole"
}
Update if Necessary:
If the trust policy is missing or incorrectly configured, update it to include the lambda.amazonaws.com service principal.
2. Option B: Verify the Execution Role's Permissions
Statement:

Check the execution role that is configured in the CloudFormation template for the Lambda function. Ensure that the execution role has the necessary permissions to write to CloudWatch Logs.

Reasoning:

CloudWatch Logs Permissions: The execution role must have permissions to create log groups, log streams, and put log events in CloudWatch Logs.

AWS Managed Policies: AWS provides a managed policy called AWSLambdaBasicExecutionRole which includes the necessary permissions (logs:CreateLogGroup, logs:CreateLogStream, and logs:PutLogEvents).

Operational Efficiency: Using AWS managed policies simplifies permission management and ensures that all required permissions are correctly configured without manual policy creation.

Implementation Steps:

Review the CloudFormation Template:
Locate the IAM role resource associated with the Lambda function.
Check Attached Policies:
Ensure that the role includes the AWSLambdaBasicExecutionRole managed policy or equivalent custom policies that grant the necessary CloudWatch Logs permissions.
Attach or Update Policies if Necessary:
If the necessary permissions are missing, attach the AWSLambdaBasicExecutionRole managed policy or add a custom policy with the required permissions. Example custom policy:
json
Copy code
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}


<img width="1436" alt="image" src="https://github.com/user-attachments/assets/77e93d35-7042-4801-af7f-89c92a962cb0">


Explanation:
To identify any Amazon EC2 instances attempting to use Network Time Protocol (NTP) servers outside of the Amazon Time Sync Service, you need to monitor the network traffic originating from those instances. Here's a detailed breakdown of why Option C is the correct choice and why the other options are less suitable:

1. Understanding the Requirements:
Prevent Unauthorized NTP Usage: Ensure that all EC2 instances exclusively use the Amazon Time Sync Service for time synchronization.
Identify Non-compliant Behavior: Detect any attempts by EC2 instances to communicate with external NTP servers on the internet.
Utilize Existing Logging Mechanisms: Leverage AWS CloudTrail and VPC Flow Logs, which are already enabled.
2. Why Option C is Correct:
Option C: Monitor VPC flow logs for traffic to non-standard time servers.

VPC Flow Logs: VPC Flow Logs capture detailed information about the IP traffic going to and from network interfaces in your VPC. This includes information about the source and destination IP addresses, ports, protocols, and whether the traffic was allowed or denied by security groups or network ACLs.

Identifying NTP Traffic: NTP typically operates over UDP port 123. By analyzing VPC Flow Logs, you can filter for traffic where the destination port is 123 and the destination IP is not part of the Amazon Time Sync Service's IP ranges.

Detecting External Access Attempts: Since the goal is to prevent and identify access to external NTP servers, monitoring VPC Flow Logs allows you to detect any outbound attempts from your EC2 instances to non-authorized NTP servers on the internet.

Operational Efficiency: This method leverages existing VPC Flow Logs without requiring additional infrastructure or complex configurations. It provides a straightforward way to monitor and alert on unauthorized NTP traffic.


<img width="1117" alt="image" src="https://github.com/user-attachments/assets/502d9b77-40af-4fbf-b767-b7c4721288ba">
Explanation:
To ensure that all new accounts within an AWS Organization become AWS Security Hub member accounts with the least development effort, the most effective approach leverages AWS Organizations' integration with Security Hub. Here's why Option D is the optimal choice:

1. Designate a Security Hub Delegated Administrator:
Delegated Administrator Role:
AWS Security Hub allows you to designate a delegated administrator account within your AWS Organization. This account manages Security Hub across all member accounts.
By centralizing management in a delegated admin account, you simplify the configuration and maintenance process.
2. Create a Configuration Policy in the Delegated Administrator Account:
Configuration Policy:
In the delegated admin account, you can create a configuration policy that specifies the enabling of Security Hub for all member accounts.
This policy ensures that any new account provisioned within the organization automatically has Security Hub enabled without manual intervention.
3. Associate the Configuration Policy with the Organization Root:
Organization-Wide Application:
By associating the configuration policy with the organization root, the policy applies universally to all existing and future member accounts.
This guarantees that every new account created through AWS Control Tower Account Factory or other provisioning methods within the organization will have Security Hub automatically enabled and configured as a member.
4. Benefits of Option D:
Minimal Development Effort:

This solution primarily involves configuration within AWS Organizations and Security Hub, avoiding the need for custom scripts, Lambda functions, or complex workflows.
Scalability:

As the organization grows and new accounts are added, the configuration policy ensures consistent Security Hub enrollment without additional steps.
Centralized Management:

Managing Security Hub from a single delegated admin account streamlines oversight, reporting, and compliance efforts.
Automated Compliance:

Ensures that all accounts adhere to security best practices by having Security Hub enabled, thereby facilitating continuous monitoring and threat detection.


<img width="1422" alt="image" src="https://github.com/user-attachments/assets/2311dbb4-a1a7-401f-9a4d-5f48a5823e61">
Explanation:
To enable Amazon GuardDuty to effectively monitor Kubernetes-based applications running on Amazon Elastic Kubernetes Service (EKS) clusters, it's crucial to ensure that GuardDuty has access to the necessary logs that capture relevant activities and potential threats. Here's a detailed breakdown of why Option D is the correct choice and why the other options are less suitable:

1. Enabling Control Plane Logs in Amazon EKS:
Control Plane Logging:
Amazon EKS Control Plane Logs (such as audit, authenticator, controllerManager, and scheduler logs) provide detailed insights into the activities within your Kubernetes clusters. These logs capture API calls, authentication attempts, and other critical events that are essential for security monitoring.
Integration with GuardDuty:
Amazon GuardDuty's EKS Protection feature relies on these control plane logs to detect anomalous behaviors, potential misconfigurations, and security threats within the Kubernetes environment.
By enabling control plane logs and directing them to Amazon CloudWatch Logs, GuardDuty can continuously analyze these logs to identify suspicious activities related to your Kubernetes-based applications.
2. Ensuring Logs are Ingested into Amazon CloudWatch:
Centralized Log Management:
Amazon CloudWatch Logs serves as a centralized repository for your EKS control plane logs. By ensuring that these logs are ingested into CloudWatch, you facilitate seamless integration with GuardDuty.
Automated Analysis:
GuardDuty automatically ingests and analyzes logs from CloudWatch Logs. This automated process enables real-time threat detection without requiring manual intervention, thus meeting the requirement for operational efficiency.
Why Option D is the Best Choice:
Direct Impact on GuardDuty Monitoring:

Enabling control plane logs and ensuring their ingestion into CloudWatch directly affects GuardDuty's ability to monitor and analyze EKS activities. Without these logs, GuardDuty lacks the necessary data to perform comprehensive threat detection for Kubernetes-based applications.
Operational Efficiency:

This solution leverages existing AWS services and integrates seamlessly with GuardDuty, minimizing the need for additional configurations or custom development. It ensures that all relevant logs are automatically available for GuardDuty to process.


Implementation Steps for Option D:
Enable Control Plane Logging in Amazon EKS:

Navigate to the EKS Console:
Go to the Amazon EKS console in the AWS Management Console.
Select the Cluster:
Choose the EKS cluster you want to configure.
Update Logging Configuration:
Under the Logging tab, enable the desired log types (e.g., audit, authenticator, controllerManager, scheduler).
Specify CloudWatch Logs:
Ensure that the logs are directed to Amazon CloudWatch Logs for centralized storage and analysis.
Verify Log Ingestion into CloudWatch:

Access CloudWatch Logs:
Open the Amazon CloudWatch console and navigate to Logs.
Confirm Log Streams:
Verify that the EKS control plane logs are being ingested into the appropriate log groups.
Ensure GuardDuty is Enabled and Configured:

Enable GuardDuty:
If not already enabled, activate Amazon GuardDuty in the us-west-2 region.
Verify EKS Protection:
In the GuardDuty console, ensure that EKS Protection is enabled to start monitoring the control plane logs for security threats.
Monitor and Respond to Findings:

Review GuardDuty Findings:
Regularly check GuardDuty for any security findings related to your EKS clusters.
Implement Remediation Actions:
Take appropriate actions based on the severity and nature of the findings to maintain a secure Kubernetes environment.


<img width="1126" alt="image" src="https://github.com/user-attachments/assets/6dc8ab58-d1b9-4100-b3ba-85d1b742d8b7">
Explanation:
To fulfill the requirements of logging object-level activity in Amazon S3 buckets and validating the integrity of the log files using a digital signature, the most effective solution involves leveraging AWS CloudTrail with specific configurations. Here's a detailed breakdown of why Option A is the optimal choice:

1. Logging Object-Level Activity:
AWS CloudTrail Data Events:
Data Events in CloudTrail provide detailed logging of API operations on specific resources. For Amazon S3, data events include operations like GetObject, PutObject, DeleteObject, etc., which are essential for tracking object-level activities.
By enabling data events for Amazon S3, you capture granular insights into how objects within your S3 buckets are accessed and modified.
2. Validating Log File Integrity:
Log File Validation in CloudTrail:
Log File Validation ensures that the CloudTrail log files have not been altered or tampered with after they are delivered to the specified S3 bucket.
When log file validation is enabled, CloudTrail creates a validation file (a hash) for each log file. This hash can be used to verify the integrity of the log file, providing a digital signature that confirms the log's authenticity and completeness.
3. Comprehensive Monitoring and Security:
Centralized Logging:
CloudTrail provides a centralized mechanism to monitor and audit API calls across your AWS environment, enhancing your ability to detect and respond to suspicious activities.
Integration with Other AWS Services:
CloudTrail logs can be integrated with services like Amazon CloudWatch Logs, AWS Lambda, and Amazon SNS for real-time monitoring, alerting, and automated responses.

<img width="1450" alt="image" src="https://github.com/user-attachments/assets/0d24bff7-f70d-48be-a31d-69a030413864">
Explanation:
To effectively mitigate credential stuffing attacks while minimizing the impact on legitimate users, the security engineer should implement measures that specifically target malicious login attempts without introducing significant friction for genuine users. Here's a detailed breakdown of why Options B and E are the most suitable choices:

1. Option B: Add the Account Takeover Prevention (ATP) AWS Managed Rule Group to the Web ACL
Statement:

Add the account takeover prevention (ATP) AWS managed rule group to the web ACL. Configure the rule group to inspect login requests to the system. Block any requests that have the awswaf:managed:aws:atp:signal:credential_compromised label.

Reasoning:

Purpose of ATP Rule Group:
The Account Takeover Prevention (ATP) rule group is specifically designed to detect and mitigate account takeover attempts, including credential stuffing attacks. It leverages threat intelligence and behavioral analysis to identify suspicious login patterns and compromised credentials.
Label-Based Blocking:
By configuring the ATP rule group to block requests with the awswaf:managed:aws:atp:signal:credential_compromised label, you ensure that only requests identified as using compromised credentials are blocked. This targeted approach prevents malicious actors from successfully accessing accounts while allowing legitimate users to continue their activities uninterrupted.
Minimized Impact on Legitimate Users:
Since the ATP rule group specifically targets compromised credentials, it avoids introducing broad restrictions (like CAPTCHAs) that could inconvenience legitimate users. Only malicious login attempts are intercepted, maintaining a seamless user experience.
Implementation Steps:

Navigate to AWS WAF Console:

Open the AWS WAF console in the AWS Management Console.
Add Managed Rule Group:

Select the relevant Web ACL associated with your Application Load Balancer (ALB).
Choose "Add managed rule group" and select the Account Takeover Prevention (ATP) rule group.
Configure Inspection and Blocking:

Ensure that the rule group is set to inspect login requests.
Configure the rule to block any requests that carry the awswaf:managed:aws:atp:signal:credential_compromised label.
Save and Deploy:

Save the changes to the Web ACL. AWS WAF will start enforcing the new rules immediately.
2. Option E: Create a Custom Block Response that Redirects Users to a Secure Workflow to Reset Their Password
Statement:

Create a custom block response that redirects users to a secure workflow to reset their password inside the system.

Reasoning:

Enhanced Security Posture:

By redirecting blocked users to a secure password reset workflow, you ensure that if legitimate users inadvertently trigger a security rule (e.g., by entering compromised credentials from another breach), they are prompted to secure their accounts promptly. This reduces the risk of unauthorized access resulting from credential stuffing.
User-Friendly Mitigation:

Unlike generic blocking mechanisms that might frustrate users, a customized response provides a clear and actionable path for users to rectify potential security issues with their accounts. This approach maintains user trust and minimizes disruption.
Automated Response:

Implementing this solution automates the response to detected threats, ensuring consistent handling of suspicious activities without requiring manual intervention.
Implementation Steps:

Create a Custom Response in AWS WAF:

In the AWS WAF console, navigate to your Web ACL.
Under "Rules", select the ATP rule group you added in Option B.
Configure Custom Response:

Choose "Add action" for the specific rule that identifies compromised credentials.
Select "Block" and then "Custom response".
Define the response to redirect users to the secure password reset workflow URL.
Define Response Parameters:

Specify the HTTP status code (e.g., 403 Forbidden).
Set the Location header to the URL of the secure password reset workflow.
Optionally, customize the response body with user-friendly messaging.
Save and Deploy:

Save the custom response configuration. AWS WAF will apply this response to any blocked requests matching the ATP rule criteria.


<img width="1446" alt="image" src="https://github.com/user-attachments/assets/daf6d9fc-deca-4d30-8373-6509ba26251b">
Explanation:
To address the company's requirements of managing cross-account access for developers in a scalable and secure manner, Option C provides the most effective and operationally efficient solution. Here's a detailed breakdown of why this is the optimal choice:

1. Leveraging IAM Roles for Cross-Account Access:
IAM Roles in Target Accounts (Testing and Production):

Purpose: Create IAM roles in the testing and production accounts that define the permissions required to access resources in those environments.
AssumeRole Policy: Attach a policy to these roles that allows the sts:AssumeRole action from trusted entities (i.e., the development account roles). This policy ensures that only authorized roles from the development account can assume these roles.
IAM Roles in Source Account (Development):

Purpose: Create IAM roles in the development account for developers who need access to the testing and production accounts.
Permissions: These roles should have the necessary permissions to assume the roles in the testing and production accounts using the sts:AssumeRole API call.
2. Minimizing Credential Sharing:
No Shared Credentials: By using IAM roles and the sts:AssumeRole mechanism, developers do not need to share or manage long-term credentials (such as access keys) across accounts. This adheres to best practices for credential management and enhances security.

Temporary Security Credentials: When a developer assumes a role in the testing or production account, AWS provides temporary security credentials that are valid for a limited duration. This reduces the risk associated with long-term credential exposure.

3. Scalability and Flexibility:
Easily Manage Access: As the number of developers or the access requirements change, IAM roles can be easily updated or new roles can be created without the need to distribute or revoke individual credentials.

Dynamic Access Control: Policies attached to roles can be dynamically adjusted to grant or restrict access based on evolving security policies or project needs.

4. Implementation Steps for Option C:
Create IAM Roles in Testing and Production Accounts:

Role Creation: In both the testing and production accounts, create IAM roles that define the permissions necessary for developers to perform their tasks.
Trust Policy: Configure the trust policy of these roles to allow assumption by specific roles from the development account. For example:
json
Copy code
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::DevelopmentAccountID:role/DeveloperRole"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
Create IAM Roles in the Development Account:

Role Assignment: For developers who need access to the testing and production accounts, create IAM roles in the development account.
Permissions Policy: Attach policies to these roles that grant permissions to assume the roles in the testing and production accounts. For example:
json
Copy code
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::TestingAccountID:role/TestingRole",
        "arn:aws:iam::ProductionAccountID:role/ProductionRole"
      ]
    }
  ]
}
Assign Roles to Developers:

Role Assignment: Assign the appropriate IAM roles to developers based on their access needs. Developers can switch roles within their AWS Management Console or use AWS CLI commands to assume roles as necessary.
Maintain and Audit Access:

Regular Reviews: Periodically review and update role permissions and trust policies to ensure they align with current security policies and access requirements.
Logging and Monitoring: Use AWS CloudTrail and IAM Access Analyzer to monitor role assumptions and ensure that access patterns remain compliant with security policies.

Benefits of Option C:
Enhanced Security: Reduces the risk associated with long-term credentials and ensures that access is granted based on defined roles and policies.

Operational Efficiency: Streamlines access management by using IAM roles and policies, allowing for easy scalability as the organization grows.

Compliance: Facilitates adherence to security best practices and compliance requirements by centralizing and automating access control mechanisms.


<img width="1423" alt="image" src="https://github.com/user-attachments/assets/4ed604fe-4cd7-4b9d-a27c-a82c816fa9cc">
Explanation:
To secure the legacy, internet-facing application against SQL injection attacks swiftly and with minimal operational disruption, Option A provides a comprehensive and efficient approach. Here's a detailed breakdown of why this option is the most suitable:

1. Implementing AWS WAF to Protect Against SQL Injection:
AWS WAF (Web Application Firewall):

Purpose: AWS WAF is designed to protect web applications from common web exploits, including SQL injection attacks.
Managed Rules: AWS provides managed rule groups, such as the Core Rule Set (CRS), which includes predefined rules to detect and block SQL injection attempts.
Customization: You can further customize the WAF rules to fine-tune the protection based on specific application needs.
Steps Involved:

Create an Application Load Balancer (ALB):

Integration Point: ALB acts as a central point for applying WAF protections before traffic reaches the EC2 instances.
Target Group: Configure the ALB to route traffic to the existing EC2 instances, ensuring that both instances are part of the load balancing setup.
Create and Configure AWS WAF Web ACL:

Rule Setup: Incorporate the AWS WAF Core Rule Set (CRS) to automatically filter out SQL injection patterns and other common threats.
Apply to ALB: Attach the WAF Web ACL to the ALB, ensuring that all incoming traffic is inspected and malicious requests are blocked before reaching the EC2 instances.
2. Maintaining Normal Operations During Implementation:
Seamless Transition:

Testing Phase: After configuring the ALB and WAF, perform thorough testing to ensure that legitimate traffic is not adversely affected and that SQL injection attempts are effectively blocked.
Gradual Rollout: Initially, you can monitor the WAF's behavior in a non-blocking mode (e.g., count or log mode) before enforcing strict blocking rules, allowing for adjustments without disrupting legitimate users.
Minimizing Downtime:

Redirection via Route 53: Once testing confirms that the WAF is effectively mitigating the SQL injection attacks, update the Amazon Route 53 records to point to the new ALB. This ensures that traffic flows through the WAF-protected ALB without requiring downtime.
Security Group Adjustments: Update the security groups attached to the EC2 instances to restrict direct internet access. This ensures that all inbound traffic must go through the ALB and, consequently, the WAF, enhancing the security posture.

4. Benefits of Option A:
Immediate Protection: AWS WAF can be rapidly deployed and configured to block SQL injection attempts, providing immediate security enhancements.
Scalability and Flexibility: As traffic patterns evolve, WAF rules can be adjusted or expanded to address new threats without significant changes to the underlying infrastructure.
Cost-Effectiveness: Utilizing managed services like ALB and AWS WAF reduces the need for additional hardware or complex configurations, optimizing both time and cost.
Implementation Steps for Option A:
Create an Application Load Balancer (ALB):

Set up an ALB in front of the existing EC2 instances.
Configure the target group to include both EC2 instances, ensuring balanced traffic distribution.
Create and Configure AWS WAF Web ACL:

Navigate to the AWS WAF console.
Create a new Web ACL and add the Core Rule Set (CRS) managed rule group.
Add additional custom rules if necessary to fine-tune protection.
Attach the Web ACL to the newly created ALB.
Test the Configuration:

Perform controlled tests to ensure that legitimate traffic is unaffected and that SQL injection attempts are blocked.
Monitor AWS WAF logs to verify that malicious requests are being correctly identified and mitigated.
Update Route 53 Records:

Once testing is successful, update the Route 53 weighted load balancing records to redirect traffic to the ALB instead of the EC2 instances directly.
Adjust Security Groups:

Modify the security groups associated with the EC2 instances to block direct inbound access from the internet, ensuring all traffic flows through the ALB and WAF.
Monitor and Optimize:

Continuously monitor the WAF and ALB performance.
Adjust WAF rules as necessary based on evolving threat landscapes and application requirements.




2024/12/12
<img width="1151" alt="image" src="https://github.com/user-attachments/assets/ed9eecb7-d30f-4162-ad17-d0b37d9c74ca">
<img width="1152" alt="image" src="https://github.com/user-attachments/assets/8cff37ef-4c19-42bf-b072-c8dba33110f0">
<img width="1133" alt="image" src="https://github.com/user-attachments/assets/2674db81-bb42-4e96-a01a-8f5788683b8a">
<img width="1119" alt="image" src="https://github.com/user-attachments/assets/f30266e8-c9b8-4e14-98d5-d4188e695b8d">
<img width="1122" alt="image" src="https://github.com/user-attachments/assets/1313dfdf-4a71-496e-89ff-5de803619196">
<img width="956" alt="image" src="https://github.com/user-attachments/assets/449e3bf5-a124-4501-993d-ebcbc2e6b0e9">
<img width="1130" alt="image" src="https://github.com/user-attachments/assets/e846dc34-3223-4b19-b6a1-0e8f2fc74a77">
 <img width="901" alt="image" src="https://github.com/user-attachments/assets/378cfba0-6c0e-436b-bb4d-6305f44e9b83">

<img width="1456" alt="image" src="https://github.com/user-attachments/assets/b317a0dd-9fd8-4df3-a832-046f4ed158c6">
Answer: D. Create an IAM role in the company’s production account. Define a trust policy that requires MFA. In the trust policy, specify the consultant agency’s AWS account as the principal. Attach the trust policy to the role.

Explanation:

The requirements are:

MFA is required for all access:
This ensures that any entity accessing the production account must authenticate using MFA.

No long-term credentials:
The solution must rely on short-term, temporary credentials. This rules out creating individual IAM users with permanent credentials in the production account.

Why Option D is the Correct Choice:

Cross-Account Role Assumption:
By creating an IAM role in the production account, you allow the consultant agency (from its own AWS account) to assume that role using temporary credentials. This follows standard best practices for secure cross-account access.

Trust Policy with MFA Requirement:
You can configure a role’s trust policy to require an MFA condition. For example, the trust policy can specify an MFA condition key (aws:MultiFactorAuthPresent) to ensure that the role can only be assumed when MFA is used on the principal (the consultant agency’s account).

No Long-Term Credentials:
IAM roles provide temporary credentials from the Security Token Service (STS), meaning no persistent keys are stored, thereby satisfying the “no long-term credentials” requirement.



<img width="1439" alt="image" src="https://github.com/user-attachments/assets/9faf5266-da2c-4a91-aed3-34546046d8fd">
Correct Answer: B and C

Explanation:

The requirements are:

Continuously monitor Lambda functions for vulnerabilities across hundreds of AWS accounts in an AWS Organizations setup.
Provide a dashboard that shows detected issues (vulnerabilities) for Lambda functions.
Exclude Lambda functions that are in test or development from appearing on the dashboard.
Why Amazon Inspector?

Amazon Inspector now includes functionality to automatically scan Lambda functions for code vulnerabilities and potential security issues. It can be set up to work across an organization with a designated delegated administrator account.
Amazon GuardDuty focuses on threat detection (e.g., suspicious activities, compromised workloads) rather than vulnerability scanning. Thus, GuardDuty is not the correct service for continuous vulnerability assessment.
AWS Shield Advanced is for DDoS protection and does not scan for Lambda vulnerabilities.
Step-by-Step Reasoning:

Centralized Management with Amazon Inspector (Option B):
Designating a delegated Amazon Inspector administrator account in the organization’s management account allows for continuous, organization-wide scanning of Lambda functions. The Inspector dashboard then provides an overview of all discovered vulnerabilities.

Filtering Out Non-Production Functions (Option C):
Applying tags such as "test" or "development" to Lambda functions under development or testing allows you to create a suppression filter. This filter ensures findings for these tagged Lambda functions are suppressed, thereby preventing them from appearing on the dashboard. This meets the requirement to exclude non-production functions from the reported vulnerabilities.



<img width="679" alt="image" src="https://github.com/user-attachments/assets/7f5c86aa-4135-4846-80f6-99223be063e4">
Answer: A. Attach a policy to the IAM user to allow the user to assume the role that was created in the top-level account. Specify the role’s ARN in the policy.

Explanation:

To allow an IAM user in a business unit account to access CloudTrail logs stored in the top-level account’s S3 bucket, the user must assume the IAM role that was created in the top-level account. The role in the top-level account grants read-only access to a specific prefix of the logs for that business unit.

The steps are typically as follows:

Create a Role in the Top-Level Account:
This role includes an IAM policy granting read-only access to the appropriate S3 bucket prefix (e.g., s3:GetObject on arn:aws:s3:::<top-level-bucket>/<business-unit-prefix>/*).
The trust policy of this role should trust the business unit account, allowing principals from that account to assume it.

In the Business Unit Account:
To let an IAM user in the business unit account use that role, you need to give the user permission to call sts:AssumeRole on the role’s ARN. This is done by attaching an IAM policy to the user (or a group the user belongs to) that includes a statement like:

json
Copy code
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::<top-level-account-id>:role/<role-name>"
}


<img width="1434" alt="image" src="https://github.com/user-attachments/assets/089519b8-b888-4378-bee3-a2593d4099fa">
Answer: A. Designate an Amazon GuardDuty administrator account in the organization’s management account. Enable GuardDuty for all accounts. Enable EKS Protection and RDS Protection in the GuardDuty administrator account.

Explanation:

The requirements are:

A solution that can monitor logs from all AWS resources across multiple accounts in an organization.
Automatic detection of security-related issues.
Minimal operational effort.
Why Amazon GuardDuty?

Centralized and Automated Threat Detection: GuardDuty is a threat detection service that continuously monitors for malicious or unauthorized activity. It automatically analyzes logs from multiple sources such as VPC Flow Logs, CloudTrail, DNS logs, and also includes EKS runtime monitoring and RDS (Aurora) protection.
Organization-Wide Setup: GuardDuty supports multi-account, organization-wide deployment using AWS Organizations, making it easy to enable and manage across hundreds of accounts from a single administrator account.
By designating a GuardDuty administrator account in the management account, you can quickly enable GuardDuty across all member accounts. Enabling EKS Protection and RDS Protection ensures that GuardDuty also analyzes signals related to EKS clusters and Aurora databases. This approach gives you immediate, continuous detection of suspicious activities without the need to build and maintain custom log processing pipelines.



<img width="1150" alt="image" src="https://github.com/user-attachments/assets/9f2098ff-dccb-4f9c-8621-1af1677befbf">
Explanation:
The problem involves a single web server not receiving inbound connections, despite correct configurations for security groups, network ACLs, and the virtual security appliance. Additional areas to check include the Elastic Network Interface (ENI) configuration and the Application Load Balancer (ALB) target registration.

Option B: Verify which security group is applied to the particular web server’s elastic network interface (ENI).
Even though the security group rules are correct, the wrong security group might be applied to the ENI of the affected web server. Each instance is associated with one or more ENIs, and the security groups attached to these ENIs control inbound and outbound traffic.
Verifying the applied security group ensures that the correct security rules are in effect.
Option D: Verify the registered targets in the ALB.
If the web server is not correctly registered as a target in the ALB, the ALB will not route traffic to it, even if all networking and security configurations are correct.
The security engineer should check whether the target (web server) is registered and in a healthy state in the ALB's target group.
Why Not the Other Options?
Option A: Verify that the 0.0.0.0/0 route in the route table for the web server subnet points to a NAT gateway.

A NAT gateway is used for outbound connections to the internet from private subnets, not for inbound connections. The requirement is about inbound traffic, so this is irrelevant.
Option C: Verify that the 0.0.0.0/0 route in the route table for the web server subnet points to the virtual security appliance.

While the architecture specifies that traffic flows through the virtual security appliance, this route setting would typically apply to outbound traffic. If inbound traffic to the subnet is not reaching the server, the issue is more likely with the ALB or ENI, as verified rules in the appliance are correct.
Option E: Verify that the 0.0.0.0/0 route in the public subnet points to a NAT gateway.

Similar to Option A, this is not relevant for inbound traffic. NAT gateways are used for outbound internet connectivity.



<img width="1131" alt="image" src="https://github.com/user-attachments/assets/2450aea9-4228-497d-afe8-a1585162196a">

Answer: B. Ensure that the operations team creates a bucket policy that requires requests to use server-side encryption with AWS KMS keys (SSE-KMS) that are customer managed. Ensure that the security team creates a key policy that controls access to the encryption keys.

Explanation:

To meet the requirement of separating duties so that no single team can inadvertently grant unauthorized access to plaintext data, you need a solution that relies on two distinct sets of permissions: one for managing S3 bucket access and another for managing encryption key usage.

Server-Side Encryption with SSE-KMS (Customer Managed Keys):

When you use SSE-KMS with a customer-managed AWS KMS key, there are two permission sets involved:
S3 Bucket Permissions: Controlled by the operations team.
KMS Key Permissions: Controlled by the security team.
With SSE-KMS, any request to decrypt or re-encrypt data in S3 must have access granted both at the S3 layer and at the KMS key layer. This inherently enforces a separation of duties.

Bucket Policy Enforced by Operations Team:

The operations team can create a bucket policy that requires all PUT requests to specify SSE-KMS with a specific KMS key. This ensures that no data can be uploaded in plaintext or with a different encryption mechanism.
The bucket policy ensures that any user accessing this bucket must comply with the encryption requirement.
Key Policy Enforced by Security Team:

The security team can create and manage a customer-managed KMS key.
The key policy can be strictly controlled by the security team, limiting which IAM principals can use the key for encryption and, more critically, for decryption.
Even if someone has S3 bucket access, they cannot decrypt the data if the KMS key policy does not allow it.




<img width="1422" alt="image" src="https://github.com/user-attachments/assets/88ef47c6-356f-4bed-b2a6-1dff84c04947">




<img width="1120" alt="image" src="https://github.com/user-attachments/assets/81424bf8-df30-48d7-ac57-30bd52113fd9">
Answer: C. Configure Amazon CloudWatch Logs as the target of the EventBridge rule. Set up a metric filter on the IncomingBytes metric and enable anomaly detection. Create an Amazon Simple Notification Service (Amazon SNS) topic. Configure a CloudWatch alarm that uses the SNS topic to send the notification.

Explanation:
To meet the requirements of generating a notification email when anomalous GetSecretValue API calls occur, the solution needs to effectively monitor, detect anomalies, and send notifications with minimal operational overhead. Here's how Option C fulfills these requirements:

EventBridge Integration with CloudWatch Logs:

Target Configuration: By configuring Amazon CloudWatch Logs as the target of the EventBridge rule, all Secrets Manager events captured by CloudTrail will be forwarded to CloudWatch Logs for further analysis.
Metric Filtering and Anomaly Detection:

Metric Filter: Setting up a metric filter on the IncomingBytes metric allows you to monitor the volume of data being accessed through GetSecretValue API calls. This metric can be indicative of abnormal access patterns.
Anomaly Detection: Enabling anomaly detection on this metric within CloudWatch helps in automatically identifying deviations from normal patterns without the need for manual threshold setting. This ensures that unusual or potentially malicious activities are promptly detected.
Notification Mechanism:

Amazon SNS Topic: Creating an Amazon SNS topic provides a scalable and reliable way to send notifications. SNS can directly send emails, SMS, or trigger other actions based on the alarm.
CloudWatch Alarm: Configuring a CloudWatch alarm that monitors the anomaly-detected metric ensures that when an anomaly is detected, the alarm triggers and sends a notification through the SNS topic. This immediate alerting mechanism satisfies the requirement for timely notifications.





Answer: A. Scan the EC2 instances by using Amazon Inspector. Apply security patches and updates by using AWS Systems Manager Patch Manager.

Explanation:

To detect and mitigate software vulnerabilities on Amazon EC2 instances running sensitive workloads, you need a two-pronged approach:

Vulnerability Detection:

Amazon Inspector provides automated security assessment capabilities. It continuously scans EC2 instances for known software vulnerabilities, network exposure, and unintended network accessibility. This helps you detect potential issues before they are exploited.
Patch Management:

AWS Systems Manager Patch Manager allows you to automatically apply patches for operating systems and applications on EC2 instances. After identifying vulnerabilities with Amazon Inspector, you can use Patch Manager to fix the issues by applying necessary updates or patches.

2024/12/11

<img width="776" alt="image" src="https://github.com/user-attachments/assets/3ea0fe8e-4643-408c-a8c5-67dc3ced5d58">


Thought for 10 seconds
Correct Answer: A

Explanation
AWS KMS is generally used to protect data keys that you use to encrypt or decrypt large amounts of data. For small amounts of data (up to about 4 KB), however, you can use KMS keys directly to encrypt the data without generating a separate data key. Since the file in question is only 2 KB, it can be encrypted directly with the aws kms encrypt command and the existing KMS key.

Why Option A Is Correct:

The aws kms encrypt command can directly encrypt small pieces of data (less than 4 KB). The 2 KB file falls within this limit.
This approach is straightforward and does not require generating and managing additional keys.
Why the Other Options Are Incorrect:

Option B: aws kms create-grant is used to delegate permissions for the KMS key to another principal. It doesn't encrypt data directly and is unnecessary here.
Option C: aws kms encrypt does not generate data keys. It directly encrypts the provided plaintext data. To generate data keys, you must use the aws kms generate-data-key command.
Option D: While aws kms generate-data-key does create a data key, you must use the plaintext data key to encrypt the file. The encrypted data key returned by the command is for storage, not for encryption. Since the file is already small enough for direct encryption, generating a data key is not required.
Conclusion
For a 2 KB file, using aws kms encrypt directly (Option A) is the simplest and most appropriate solution.

<img width="891" alt="image" src="https://github.com/user-attachments/assets/f4808815-572a-4726-9728-9c915004add7">
<img width="791" alt="image" src="https://github.com/user-attachments/assets/a82d543e-a8d8-4251-a60e-8838e932dba5">


<img width="1137" alt="image" src="https://github.com/user-attachments/assets/801e9464-ff5f-40d2-9ba9-d644b9445d1b">
<img width="1131" alt="image" src="https://github.com/user-attachments/assets/5a59f739-d2e0-48c8-93ea-7c844ea82c33">


Thought for a few seconds
Correct Answer: B

Explanation
Amazon Cognito user authentication events, including successful and unsuccessful login attempts, are recorded by AWS CloudTrail when Cognito is used as an identity provider. Each login attempt can be identified by the InitiateAuth event name, and the event source will be cognito-idp.amazonaws.com.

Key Steps:

Enable AWS CloudTrail: By enabling CloudTrail for your AWS account, login attempts to Cognito user pools are captured.
Delivery to Amazon S3: The CloudTrail logs are delivered to an S3 bucket.
Query with Amazon Athena: Using Athena, you can write SQL queries to filter the CloudTrail logs stored in S3 by event name (InitiateAuth) and event source (cognito-idp.amazonaws.com). This lets you analyze both successful and failed login attempts.
Why Option B is Correct
Full Audit of Login Attempts: CloudTrail logs all API calls, including Cognito login attempts (InitiateAuth events), enabling a complete record of user activities.
Query with Athena: Once the logs are in S3, Athena can efficiently query the JSON-formatted CloudTrail logs using standard SQL. This provides a convenient way to filter on event name, event source, and success or failure attributes.



<img width="697" alt="image" src="https://github.com/user-attachments/assets/2cec1d4a-64a0-4af9-830a-6a6f3f00abd0">
<img width="905" alt="image" src="https://github.com/user-attachments/assets/817026fd-c01f-4de1-aed5-22e997d2a123">

<img width="1147" alt="image" src="https://github.com/user-attachments/assets/8f0b650d-dad1-4ca5-95e3-b0730d1cb605">

<img width="1148" alt="image" src="https://github.com/user-attachments/assets/60ee992d-2ae7-4af1-9f4b-5c5f44a5a77d">
<img width="657" alt="image" src="https://github.com/user-attachments/assets/489b42f1-591b-44b1-b1cd-070850f365d6">




<img width="717" alt="image" src="https://github.com/user-attachments/assets/88a6af15-3f0e-47d8-81a3-ad61996617ee">


Thought for a second
Correct Answer: A

Explanation
The requirement is to automatically report vulnerabilities discovered by Amazon ECR enhanced scanning to a Slack channel. The scanning engine for ECR images is integrated with Amazon Inspector, which means the findings will appear as Amazon Inspector findings. The simplest and most operationally efficient solution involves using Amazon EventBridge, Amazon SNS, and AWS Chatbot together:

Amazon Inspector:
Configure Amazon Inspector to run enhanced scans on the ECR repository. When vulnerabilities are found, Inspector generates findings.

EventBridge Rule:
Create an EventBridge rule that triggers on Amazon Inspector findings. This avoids manual polling or complex orchestration.

Amazon SNS:
Set the EventBridge rule to send the Inspector findings to an SNS topic. SNS acts as a message hub and can fan out notifications to multiple endpoints.

AWS Chatbot:
Configure AWS Chatbot with Slack to consume messages from the SNS topic. AWS Chatbot provides a native integration with Slack, making it straightforward to deliver notifications to a Slack channel.

This combination leverages managed services with minimal coding and infrastructure. The pipeline is event-driven and serverless, ensuring high operational efficiency and reduced maintenance overhead.



<img width="783" alt="image" src="https://github.com/user-attachments/assets/df263e54-3aa3-4729-8161-bf3c85401b35">
<img width="774" alt="image" src="https://github.com/user-attachments/assets/aecbf9b3-d31d-43bf-abb1-a31d27e588f7">


<img width="846" alt="image" src="https://github.com/user-attachments/assets/464b585f-e718-4be8-ad8d-c56cc963052e">
<img width="1136" alt="image" src="https://github.com/user-attachments/assets/902857bf-3052-44de-9d96-993212b1ba77">



<img width="824" alt="image" src="https://github.com/user-attachments/assets/fd68943c-1e90-4bd5-bf7f-69ec116d7a7b">


<img width="707" alt="image" src="https://github.com/user-attachments/assets/28764493-8b87-4164-8800-976fb14d6158">
Explanation
The Condition element in an Amazon S3 bucket policy can be used to restrict access based on specific attributes of the request. To ensure that only AWS accounts within the production OU can write VPC flow logs to the S3 bucket, the aws:SourceOrgPaths condition key should be used. This condition key allows the policy to check whether the request originates from an AWS account that is part of a specific organizational path in AWS Organizations.

Why Option B is Correct:
aws:SourceOrgPaths Key:

The aws:SourceOrgPaths key checks the organizational path of the requester in AWS Organizations.
By specifying the path to the production OU, the bucket policy ensures that only requests originating from accounts within the production OU can write to the bucket.
Organizations Entity Path:

The entity path of the production OU uniquely identifies the organizational structure leading to the production OU.
Example entity path: /Root/Production.
Aligns with Requirements:

This approach ensures access is restricted only to accounts in the production OU, meeting the requirement precisely.


<img width="1149" alt="image" src="https://github.com/user-attachments/assets/935ce876-be47-4991-a90c-9c27f5b46369">

<img width="737" alt="image" src="https://github.com/user-attachments/assets/fb373d9f-b636-4f3f-abb6-1ca82ea89723">


<img width="1142" alt="image" src="https://github.com/user-attachments/assets/9e3f2add-4764-4065-b86c-765b857d39e9">
Explanation
The solution must meet the following requirements:

Allow application teams to provision their own IAM roles.
Limit the scope of IAM roles.
Prevent privilege escalation.
Minimize operational overhead.
Service Control Policies (SCPs) and permissions boundaries work together to enforce security controls across AWS accounts managed by AWS Organizations. By using these features, the security team can delegate role provisioning to application teams while maintaining centralized control over the permissions and scope of those roles.

Why Option D is Correct:
Service Control Policies (SCPs):

SCPs control the maximum permissions allowed for all IAM roles in the organization.
By attaching an SCP to the root OU, the security team can enforce global restrictions across all accounts and ensure that only roles with specific boundaries can create new roles.
Permissions Boundaries:

Permissions boundaries restrict the maximum permissions that IAM roles can grant to other roles or entities.
This ensures that application teams cannot create roles with more privileges than allowed by the boundary.
Delegation with Control:

Application teams can create their own roles without waiting for the security team, reducing operational overhead.
The permissions boundary ensures that the roles adhere to company policies and do not result in privilege escalation.
Least Operational Overhead:

SCPs and permissions boundaries require one-time setup and apply automatically to all accounts, reducing the need for ongoing manual intervention.

<img width="705" alt="image" src="https://github.com/user-attachments/assets/7a7134fb-edb0-41db-b0e0-df26a6e55632">



<img width="1125" alt="image" src="https://github.com/user-attachments/assets/9a81a273-168e-475f-b5d9-c2c7fa419099">


<img width="1108" alt="image" src="https://github.com/user-attachments/assets/cf846901-01f3-496c-9ec5-8ef2e4ea43a3">
Explanation
For AWS KMS keys with imported key material, you cannot enable automatic rotation. Keys with imported key material do not support auto-rotation due to the external management of the key material. To meet an annual rotation requirement, you must manually rotate the key by creating a new key with new imported key material and then pointing the key alias to the new key.

Steps to Rotate a Key with Imported Material:

Create a new customer managed key in AWS KMS and specify that you will import the key material.
Generate and securely store the new key material according to your cryptographic policies.
Import the new key material into the newly created KMS key.
Update the key alias that your applications use to reference the new KMS key. This ensures that any systems using the alias will now use the rotated (new) key material without code changes.
Retire or schedule deletion of the old key, if appropriate, after ensuring a smooth transition and that no workloads depend on it.
By following these steps, you comply with the company's yearly key rotation requirement and maintain a transparent process for users and applications relying on the alias.


<img width="1140" alt="image" src="https://github.com/user-attachments/assets/009f5ff5-c2b7-43c6-91d4-ad898927fa4a">

<img width="1106" alt="image" src="https://github.com/user-attachments/assets/d6c1b93a-799e-4c1d-8754-51472ea5c371">


<img width="1132" alt="image" src="https://github.com/user-attachments/assets/7a609f0b-a96e-4133-9f7a-ed8081fb3788">


<img width="1123" alt="image" src="https://github.com/user-attachments/assets/f895faf6-edab-418c-ac28-5a595aa7bf4a">
Explanation
Amazon Macie recently introduced automated discovery which continuously and intelligently samples data from Amazon S3 buckets across the environment. This feature automatically identifies buckets that are likely to contain sensitive data based on the sampling results. When suspicious findings occur, security teams can then decide to run targeted, full scans on those specific buckets to further investigate and confirm the presence of sensitive data.

Why Option C is Correct:

Minimal Administrative Overhead:
Automated discovery reduces manual effort by continuously evaluating your buckets without requiring you to set up scheduled scans or event-based triggers.
Scalability and Efficiency:
Macie automatically samples data from all the S3 buckets, providing an overview of which buckets may contain sensitive data. This makes it easier and more efficient to focus subsequent full scans only on those high-priority buckets.
How It Works:

Enable Macie automated discovery: Macie begins analyzing and profiling S3 buckets on an ongoing basis.
Identify Potential Risk: Macie’s sampling identifies buckets that contain data patterns indicative of sensitive information.
Focused Full Scans: Once a bucket is flagged as potentially containing sensitive data, the security engineer can run a detailed Macie scan on that specific bucket for a comprehensive analysis.




<img width="1125" alt="image" src="https://github.com/user-attachments/assets/3db076e5-df6f-4b2b-810d-7a44d662e61d">


Thought for a couple of seconds
Correct Answer: C

Explanation
The requirement is to ensure that the application running behind a Network Load Balancer (NLB) in the parent company’s AWS account is only accessible to subsidiary companies, not exposed to the public internet. Managing allow lists with 1,500 subsidiary CIDR blocks for direct inbound traffic would be cumbersome and not easily scalable.

Key Points:

The NLB is a Layer 4 load balancer and does not support security groups.
Using network ACLs (NACLs) or security groups directly to whitelist thousands of CIDR blocks is complex and inefficient.
The application needs to remain private and restricted to known internal parties (the subsidiaries).
Option C: AWS PrivateLink

AWS PrivateLink provides private connectivity between VPCs, AWS services, and on-premises applications without exposing traffic to the public internet.
By creating an endpoint service associated with the NLB in the parent company’s account, you allow subsidiary AWS accounts to create interface endpoints in their VPCs.
These interface endpoints provide private, secure access to the application over AWS’s internal network, bypassing the public internet entirely.
You only need to maintain a single set of rules in the parent account’s security group that grants access to the traffic from the PrivateLink endpoints.
Each subsidiary account sets up a PrivateLink interface endpoint to connect to the parent’s endpoint service. This securely scales to 1,500 subsidiaries without managing large allow lists of CIDR blocks.
Why Not the Other Options?

Option A (NACL): NACLs are stateless and must be applied at a subnet level. Managing thousands of CIDR blocks in a NACL is error-prone and not easily scalable. Also, NACLs do not attach directly to NLBs or instances in a way that selectively enforces application-level access.
Option B (Security Groups on NLB): Network Load Balancers do not support security groups. The approach of listing 1,500 CIDR blocks in a security group and applying it to the NLB is not possible.
Option D (Security Groups with 1,500 CIDR Blocks on Instances): While you can attach a security group to EC2 instances, adding 1,500 CIDR blocks is cumbersome and not easily maintainable. Also, this still doesn’t prevent the NLB from being publicly reachable unless you also restrict NLB access routes. It doesn’t solve the scaling problem effectively.

<img width="1144" alt="image" src="https://github.com/user-attachments/assets/b2da0462-13c3-4f96-8ef2-f034de68d22f">
Explanation
The company needs a solution that continually scans Amazon EC2 instances for software vulnerabilities and unintended network exposure. Amazon Inspector is specifically designed to address these requirements by scanning EC2 instances and container images in Amazon Elastic Container Registry (ECR) for vulnerabilities and misconfigurations.

Why Option A is Correct:
Amazon Inspector:

It is a fully managed service designed to automatically scan EC2 instances and ECR repositories for software vulnerabilities (e.g., CVEs) and unintended network exposure.
It uses hybrid scanning to perform vulnerability assessments and network exposure analysis.
How It Works:

Inspector runs vulnerability scans based on CVE databases to detect software vulnerabilities in installed packages.
Inspector also monitors EC2 instance network configurations to identify unintended exposure.
Findings are automatically prioritized and sent to AWS Security Hub or Amazon EventBridge for notifications and actions.
Scan Mode:

The hybrid scanning mode combines vulnerability scanning with network reachability analysis to provide a comprehensive security assessment.


<img width="1137" alt="image" src="https://github.com/user-attachments/assets/d4fe4be7-1b23-4fc8-978c-b75f94dca32a">
Why Option B is Correct:
AWS Config Compliance Change Events:

AWS Config generates compliance change events whenever a resource’s compliance status changes (e.g., from COMPLIANT to NON_COMPLIANT or vice versa).
These events are automatically sent to EventBridge.
Amazon EventBridge Rule:

An EventBridge rule can be configured to capture compliance change events for the restricted-ssh rule.
The rule can target an Amazon SNS topic, which provides the notification to the appropriate recipients.
Near-Real-Time Notifications:

EventBridge ensures near-real-time delivery of compliance notifications without the need for additional infrastructure like Lambda or CloudWatch.
Steps:

Configure the restricted-ssh managed rule in AWS Config.
Create an EventBridge rule that filters compliance change events for the restricted-ssh rule.
Set the EventBridge rule to send notifications to an Amazon SNS topic.
Subscribe the desired endpoints (email, SMS, etc.) to the SNS topic.

<img width="1456" alt="image" src="https://github.com/user-attachments/assets/d0a6e146-1471-4dc0-be1b-b1716e45941d">
Explanation
To enforce a required minimum password length for user passwords in the given environment, the security engineer needs to address the configurations for both AWS Cognito user pools and on-premises Active Directory (AD), as these are the systems managing user authentication.

Why B (Update the password length policy in the Cognito configuration) is Correct:
Amazon Cognito user pools have a built-in password policy configuration.
The security engineer can directly set a minimum password length requirement in the Cognito user pool settings.
This ensures that all users managed in the Cognito user pool comply with the updated password length policy.
Steps:

Navigate to the Cognito user pool in the AWS Management Console.
Update the password policy to enforce a minimum password length under Policies > Password policy.
Why C (Update the password length policy in the on-premises Active Directory configuration) is Correct:
For users authenticated through IAM federated with on-premises Active Directory, password policies are controlled by the Active Directory configuration.
The minimum password length requirement must be set in the Active Directory domain security policy to ensure compliance.
Steps:

Access the Active Directory domain controller.
Update the Password Policy to specify the desired minimum password length.



<img width="1132" alt="image" src="https://github.com/user-attachments/assets/db9e277e-a699-4ce7-a17d-afa597d007ef">
Explanation
When an EBS volume is encrypted with a customer managed KMS key that uses imported key material, the EBS volume’s data key can only be decrypted by that same key material. If the key material is deleted, the key becomes unusable, meaning that no new decrypt operations can be performed using that key.

To recover and decrypt the data key for the EBS volume (and thereby regain access to the data), you must restore the original key material that was used to encrypt the volume.

Key Points:

Reimporting the Same Key Material:
By reimporting the exact same key material into the existing customer managed key, you recreate the key’s original state. This allows AWS KMS to use the restored key to decrypt the EBS volume’s data key.

No Need to Create a New Key:
Creating a new key or importing new (different) key material will not help because the EBS volume is associated with the original key and key material. To decrypt the volume, you must have the original key material back in place.

Once the Key is Restored:
After successfully reimporting the same key material, the EBS volume can be attached to the EC2 instance and accessed as normal, since the KMS key can now decrypt the volume’s data key.



<img width="1135" alt="image" src="https://github.com/user-attachments/assets/adca47a9-3d8d-471f-a463-4a56a737bf7b">

Explanation
Application Load Balancer (ALB) access logs are natively delivered to Amazon S3. From there, the standard best practice for analyzing and visualizing these logs involves the following steps:

S3 for Log Storage:
ALBs can be configured to write access logs directly to an S3 bucket. This is the only native, built-in logging option for ALB access logs.

Analysis with Amazon Athena:
After the logs are in S3, you can use Amazon Athena (a serverless, interactive query service) to query the ALB logs using standard SQL. Athena integrates directly with S3, allowing you to easily filter login attempts, identify suspicious IPs (e.g., bots), and extract insights.

Visualization with Amazon QuickSight:
Once you have queried and refined the data in Athena, you can connect Amazon QuickSight directly to Athena to create dashboards and visualization charts. QuickSight enables you to build rich, interactive visualizations of the login data, making it easy to spot trends, anomalies, and suspicious activity coming from known bad IPs.



<img width="1163" alt="image" src="https://github.com/user-attachments/assets/9323aa97-411a-4a57-823e-a216e54ecfd5">

Explanation
For forensic preservation, it is essential to:

Isolate the instance from any automated changes or additional traffic. This means removing it from the Auto Scaling group and deregistering it from the Application Load Balancer (ALB) so that no further changes occur.
Capture volatile data (memory snapshot) while the instance is still running. Memory is ephemeral, so it must be collected before the instance is stopped to preserve evidence that only exists in memory.
Create a snapshot of the EBS volume to preserve disk-based evidence. This ensures you have a point-in-time copy of the disk data.
Stop the instance to prevent further changes and maintain the state of the preserved evidence.
Let's analyze the options:

Option A: Takes EBS snapshot and memory snapshot before isolating the instance. This leaves a window where the instance could be modified by the scaling group or receive traffic from the ALB, potentially contaminating the evidence.

Option B: Takes the memory snapshot first but does not isolate the instance before doing so. The instance is still subject to changes from the scaling group and traffic from the ALB, which may alter evidence during collection.

Option D: Involves stopping the instance before taking a memory snapshot. Once an instance is stopped, memory is lost. This makes a memory snapshot impossible and fails the requirement to preserve volatile evidence.


<img width="718" alt="image" src="https://github.com/user-attachments/assets/0c79e9b9-f9ed-4aad-9fbb-ef23e2c903af">


<img width="1198" alt="image" src="https://github.com/user-attachments/assets/4abe9b8f-ebf3-4fde-a9cc-9005e285a73c">
Explanation
The requirements are:

No AWS API calls from the EC2 instances can travel over the internet.
This means all traffic to S3 and KMS must remain within the AWS network, and must use VPC endpoints.

Use existing code without changes:
The solution must allow all required actions without code changes, so we need to ensure that all necessary S3 actions (including PutObjectAcl if currently used by the application) and KMS actions are allowed through the endpoints.

Cross-account access with encryption:
The S3 bucket and the KMS key are in Account A, and the EC2 instances are in Account B. The solution must ensure that Account B can use a private path to access S3 (gateway endpoint) and KMS (interface endpoint).

Analyzing the Options
Option A: Gateway VPC endpoint for S3 in Account B

A gateway VPC endpoint for Amazon S3 is the standard, cost-effective approach to provide private network access to S3.
The resource policy of the gateway endpoint can allow s3:GetObject, s3:ListBucket, s3:PutObject, and s3:PutObjectAcl actions as needed by the application.
This ensures that S3 requests do not go over the internet.
Option C: Interface VPC endpoint for KMS in Account B with private DNS on

By default, KMS is accessed via public endpoints. To keep the KMS traffic internal and not route over the internet, you must use a VPC interface endpoint.
Enabling private DNS ensures the KMS API calls are directed to the VPC endpoint instead of the public endpoint, keeping traffic internal.
The resource policy on the interface endpoint can be configured to allow kms:Encrypt, kms:Decrypt, and kms:GenerateDataKey so that the EC2 instances can work with the encrypted S3 objects.
This combination allows both S3 and KMS operations to remain within AWS internal networks, meeting the security and compliance needs without code changes.



<img width="1118" alt="image" src="https://github.com/user-attachments/assets/99a688dd-5327-4df3-8c5d-22666ee8593c">


Thought for 4 seconds
Correct Answer: A

Explanation
The question asks for the most operationally efficient method to generate a least privilege IAM policy. AWS provides tools to simplify this process, specifically IAM Access Analyzer’s policy generation feature, which can create a policy based on actual resource usage extracted from CloudTrail events.

Option A:

Approach:
Set up a CloudTrail trail for management events.
Run the script with the existing broad permissions (the AWS managed policies).
Use IAM Access Analyzer to generate a policy from the recorded activity in CloudTrail.
Replace the existing policies with the newly generated least privilege policy.
Why This Is Efficient:
By running the script with existing broad permissions, you capture all the required API calls and actions that the script uses. Then, IAM Access Analyzer can automatically generate a policy that includes only the permissions that the script actually needed. This approach is straightforward, does not require trial-and-error, and ensures minimal guesswork.



<img width="1163" alt="image" src="https://github.com/user-attachments/assets/01958b6c-198c-46c4-9be8-6ede49475314">
AWS Nitro Enclaves provide an isolated environment that is ideal for processing sensitive data, such as credit card numbers. They offer strong security guarantees by isolating the tokenization process from other components of the application, ensuring that sensitive data is protected and inaccessible to unauthorized components


<img width="1123" alt="image" src="https://github.com/user-attachments/assets/fc6faa88-d389-497d-b1ce-cfed9555dc9e">



<img width="1119" alt="image" src="https://github.com/user-attachments/assets/36d76781-e44b-466f-bb1f-46fb030cbdb7">
Explanation
The company wants to receive automated email notifications when AWS access keys from developer accounts are detected on code repository sites. This scenario aligns with Amazon GuardDuty, which has a specific finding type that detects when AWS access keys are exposed in public code repositories, such as GitHub.

Why Option A is Correct:
A. Create an Amazon EventBridge rule for GuardDuty findings.

GuardDuty Findings: GuardDuty generates findings for security-related events, including the UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration finding type, which identifies when AWS credentials (e.g., access keys) are detected in public repositories or used in an unauthorized manner.
EventBridge Rule: EventBridge can be configured to react to specific GuardDuty findings and trigger actions, such as sending email notifications via Amazon SNS.
Email Notifications: By connecting EventBridge to an SNS topic with email subscriptions, the company can receive real-time notifications when such events occur.
Steps to Implement:

Enable Amazon GuardDuty in all accounts.
Create an SNS topic and subscribe email recipients to it.
Create an EventBridge rule to capture GuardDuty findings with the specific finding type UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.
Configure the EventBridge rule to send notifications to the SNS topic.


<img width="1173" alt="image" src="https://github.com/user-attachments/assets/ea2233ee-a82c-4e01-b2fc-030c43efa8e1">

<img width="1119" alt="image" src="https://github.com/user-attachments/assets/10d88aee-b35e-468f-99cb-d542de8f7c2d">
Explanation
When setting up AWS Security Hub for a multi-account, multi-Region environment under AWS Organizations, two key steps simplify ongoing management:

Automatically manage organizational accounts:
By enabling Security Hub's organization management features, you can have Security Hub automatically enable member accounts as they join the organization. This removes the need for manual intervention.

Aggregated view of findings across Regions:
Configuring a single aggregation Region and linking other Regions to it allows you to have a centralized, aggregated view of Security Hub findings. This setup ensures that Security Hub automatically collects findings from all AWS Regions, reducing the complexity of managing multiple standalone configurations.

Why Option A?
A. Configure a finding aggregation Region for Security Hub. Link the other Regions to the aggregation Region.

This approach gives you a single pane of glass for findings from multiple Regions.
Security Hub supports cross-Region aggregation natively. By designating one Region as the aggregation point, you centralize monitoring and reduce operational overhead.
Why Option C?
C. Turn on the option to automatically enable accounts for Security Hub.

Security Hub offers an organization management feature. When enabled, it automatically includes existing and newly added AWS accounts in the organization as members in Security Hub.
This ensures that you don't have to manually register each account. As soon as a new account joins the organization, it will be managed by Security Hub.


<img width="1127" alt="image" src="https://github.com/user-attachments/assets/b6868ffc-0a0f-44c0-bbdc-7ec9a9df0a0d">



<img width="1130" alt="image" src="https://github.com/user-attachments/assets/3d25fe27-328d-4aab-bddf-db370a8a07fc">


 <img width="1183" alt="image" src="https://github.com/user-attachments/assets/1038c6f8-1203-4934-a86d-efe553709564">
<img width="1153" alt="image" src="https://github.com/user-attachments/assets/c5d552b7-89af-494d-af0f-0054f8dc7808">
Option D: Use a Customer Managed KMS Key for Cross-Region Replication

Replication to us-west-1: Secrets Manager supports cross-Region replication, which allows you to replicate secrets from one Region to another. Replicating the secrets ensures that workloads in the secondary Region (us-west-1) can access secrets locally, reducing latency and ensuring availability if the primary Region (us-east-1) is unavailable.
Customer Managed KMS Key for Encryption: Using the same customer managed KMS key across Regions provides consistency and control over encryption. Customer managed keys allow explicit permission settings, lifecycle control, and auditing.
Latency Minimization and Resilience: By replicating secrets to us-west-1, resources in us-west-1 can access secrets directly in their Region, reducing latency compared to accessing Secrets Manager endpoints in us-east-1.


<img width="1128" alt="image" src="https://github.com/user-attachments/assets/21658359-4305-4830-9650-f996831f9bae">
Explanation
The setup is as follows:

An Application Load Balancer (ALB) in public subnets with network ACL (NACL1).
EC2 application instances in private subnets with network ACL (NACL2).
An RDS PostgreSQL database in a private subnet with network ACL (NACL3).
Currently, all NACLs allow all inbound and outbound traffic. The goal is to enhance security by restricting traffic, while still maintaining functionality. We need to ensure:

The RDS instance (in the NACL3 subnet) only allows inbound traffic on its PostgreSQL port (5432) from the application instances, not from anywhere else.
The RDS instance can return responses to the application instances by allowing outbound ephemeral ports (1024-65535).
Default "allow all" rules are removed to improve security.
Option B achieves this by:

Adding a rule in NACL3 to allow inbound traffic on port 5432 from the CIDR blocks of the application instance subnets (NACL2’s subnets). This ensures only the application servers can access the database.
Adding a rule in NACL3 to allow outbound traffic on ephemeral ports (1024-65535) back to the application instance subnets. This ensures return traffic from the database to the application instances is allowed.
Removing the default "allow all" inbound and outbound rules from NACL3 to tighten security and restrict any other unexpected traffic.


<img width="1122" alt="image" src="https://github.com/user-attachments/assets/b7e2340c-9531-426d-8af1-164e57d43c43">
Explanation
The requirement is to have a disaster recovery solution that can restore operations if an attacker bypasses existing security controls, with a Recovery Point Objective (RPO) of 1 hour. The chosen solution should enable restoration of EC2 instances (including EBS volumes) and S3 data within 1 hour of data loss.

Option A:

AWS Backup:
By taking backups of EC2 instances (including EBS volumes) and S3 buckets every hour, the RPO requirement of 1 hour can be met. In the event of a ransomware attack or system compromise, these backups provide a recent restore point.

AWS CloudFormation Templates and AWS CodeCommit:
Storing infrastructure as code (IaC) in CloudFormation templates and version-controlling them in CodeCommit allows the company to quickly and consistently re-provision infrastructure if needed. This ensures that the entire environment—compute, storage, and configuration—can be restored rapidly and consistently, meeting the recovery goal.

This approach creates a comprehensive disaster recovery solution with automated hourly backups and a reproducible infrastructure setup, satisfying the 1-hour RPO requirement.


2024/12/10
<img width="1149" alt="image" src="https://github.com/user-attachments/assets/a01cd1b7-4ed7-49b8-baf7-34c44b9aae93">

<img width="1132" alt="image" src="https://github.com/user-attachments/assets/765457f7-b52d-43e1-864c-876cd8eb633d">

<img width="881" alt="image" src="https://github.com/user-attachments/assets/ad88f3c9-edfc-4af5-8d79-71bf6ac3be6d">
Explanation
The requirement is to provide scalable, role-based access across a growing number of AWS accounts, all managed under AWS Organizations, while integrating with an external corporate Identity Provider (IdP).

Option C: Enable AWS IAM Identity Center (formerly AWS SSO) and Integrate with the Existing IdP

IAM Identity Center Integration: IAM Identity Center can be easily integrated with external IdPs using standards like SAML or OIDC. This provides a centralized place to manage access across all AWS accounts in your organization.
Permission Sets: Instead of creating IAM roles individually in each account, you can use IAM Identity Center’s permission sets. A permission set acts as a blueprint for access that can be assigned to users or groups, and it automatically creates the required roles and permissions in each target account.
Scalability and Operational Efficiency: As the company grows and adds more accounts, IAM Identity Center can quickly apply the same permission sets to new accounts without manual role creation. This dramatically simplifies ongoing administration.

<img width="1137" alt="image" src="https://github.com/user-attachments/assets/1bca5261-6b7c-43d4-8505-22301c119676">

<img width="1151" alt="image" src="https://github.com/user-attachments/assets/e3192ef4-7807-4764-9f9e-3a98aabeb318">


<img width="1133" alt="image" src="https://github.com/user-attachments/assets/4fd26cdc-cd97-483d-aa0d-653620456513">
<img width="858" alt="image" src="https://github.com/user-attachments/assets/f2d5417b-d99f-4bb2-af65-2fb5a1b8ecc5">


<img width="973" alt="image" src="https://github.com/user-attachments/assets/f55fcf82-a023-4c1e-8b09-3f3a8f9f4f3f">

<img width="899" alt="image" src="https://github.com/user-attachments/assets/9ba3db67-f0f5-4b8b-a106-294f433b104d">
<img width="768" alt="image" src="https://github.com/user-attachments/assets/fdf4ad85-6f19-4f93-987a-152311f6cd24">

<img width="847" alt="image" src="https://github.com/user-attachments/assets/0e635851-5a4a-484c-9ed6-c6f5a9e819a5">
<img width="786" alt="image" src="https://github.com/user-attachments/assets/1323a9a8-7ba3-40b9-84a5-26605af8fb54">

<img width="1122" alt="image" src="https://github.com/user-attachments/assets/2bb85b5c-d96e-4955-82db-f42272adcd74">


<img width="1135" alt="image" src="https://github.com/user-attachments/assets/32591c01-f70d-4ef4-9016-e4493ce3f91c">
<img width="747" alt="image" src="https://github.com/user-attachments/assets/da78ca90-3326-40f4-89bd-2eebdcd7038a">


<img width="1103" alt="image" src="https://github.com/user-attachments/assets/dcfe6005-75a0-4cbf-ba06-0de343554054">
Explanation
The company suspects that an attacker has obtained temporary credentials from the EC2 instance metadata and used them to access internal resources. To determine if these credentials were used from an external account, the best approach is to use a service that can detect and report such suspicious activities without manual analysis.

Option A: GuardDuty Findings (InstanceCredentialExfiltration)

Amazon GuardDuty monitors continuously for malicious or unauthorized behavior.
GuardDuty findings include "InstanceCredentialExfiltration" events, which indicate that credentials from an EC2 instance were exposed and potentially used elsewhere.
If these credentials were indeed used externally, GuardDuty would generate a corresponding finding that the security engineer can review. This provides near real-time and direct evidence of the credentials being misused by an external entity.


<img width="1131" alt="image" src="https://github.com/user-attachments/assets/bcb442be-47ef-4c68-be87-c28f268f9f3d">
Explanation
The requirement is to deploy a production CloudFormation stack with minimal privileges and maintain separation of duties between the security engineer’s IAM account and CloudFormation. The security engineer should not directly have the extensive permissions required to build the stack. Instead, CloudFormation should assume a role that has exactly the necessary permissions.

Option A: Use IAM Access Analyzer for Least Privilege and Role Separation

IAM Access Analyzer Policy Generation: This tool can analyze the CloudFormation templates and generate a policy that grants only the permissions needed to create and manage the stack’s resources.
Least Privilege: By using IAM Access Analyzer, the resulting policy will be tightly scoped to exactly what the CloudFormation stack needs, satisfying the principle of least privilege.
Separation of Duties: The generated policy is attached to a new IAM role. The security engineer does not get direct resource permissions. Instead, the engineer only needs permission to pass that role to CloudFormation (iam:PassRole). CloudFormation then acts on behalf of the engineer with the minimal required permissions. This ensures the security engineer’s IAM user does not directly have broad permissions to EC2 or RDS.


<img width="1118" alt="image" src="https://github.com/user-attachments/assets/be880d32-4fd9-4c3c-9a83-7096b534e260">
Why Option A?
A. Create CloudFormation templates in an administrator AWS account. Share the stack sets with an application AWS account. Restrict the template to be used specifically by the application AWS account.

By maintaining the CloudFormation templates in a central (administrator) AWS account, you gain a single authoritative source of truth for infrastructure definitions.
Using AWS CloudFormation StackSets, you can deploy standardized infrastructure across multiple AWS accounts from the central account.
Restricting the use of the template ensures that only approved templates (which can enforce naming conventions and resource configurations) are used for provisioning, satisfying the requirement that all infrastructure be deployed from CloudFormation templates.
This step helps ensure that deployments are consistent and compliant with internal policies (e.g., naming conventions for DynamoDB tables, and ensuring EC2 instances are launched only from approved accounts).

Why Option D?
D. Use SCPs to prevent the application AWS account from provisioning specific resources unless conditions for the internal compliance requirements are met.

Service Control Policies (SCPs) apply organization-wide and can restrict what actions can be performed by member accounts.
By using SCPs, you can prevent application accounts from creating resources outside of approved CloudFormation templates. For example, you can deny direct resource creation via the AWS Management Console, CLI, or SDK if it does not come from the specified CloudFormation roles or stack sets.
This enforces the principle that all infrastructure changes must come through CloudFormation, ensuring compliance and preventing circumvention of established controls.


2024/12/06

<img width="1129" alt="image" src="https://github.com/user-attachments/assets/78a52a4d-b122-45f9-9cac-1be8dbd562ac">
<img width="831" alt="image" src="https://github.com/user-attachments/assets/b7af99ed-8108-45ae-a0fb-a7ff16f4dbd3">


<img width="1326" alt="image" src="https://github.com/user-attachments/assets/4cbeb1e6-7c36-4478-91c6-3d8e134f11f7">
<img width="843" alt="image" src="https://github.com/user-attachments/assets/97784816-1968-4d6a-a95f-181b3333ab8a">


<img width="1356" alt="image" src="https://github.com/user-attachments/assets/d3699f28-a154-4e92-bfa2-414a43b19a4d">
<img width="872" alt="image" src="https://github.com/user-attachments/assets/aea0e3f2-f758-4c24-b620-d5d3cc45b30e">


<img width="1122" alt="image" src="https://github.com/user-attachments/assets/b8aedf00-4802-4275-800a-b20b6f5abae8">
<img width="840" alt="image" src="https://github.com/user-attachments/assets/9c7cd09b-271f-4e23-a0ac-f1729e8cc355">

<img width="1111" alt="image" src="https://github.com/user-attachments/assets/d54bbbdf-a4a6-45a5-a61f-fb9c1492e845">

<img width="1121" alt="image" src="https://github.com/user-attachments/assets/3491c344-9558-4101-8bdf-e7b529c6e006">

<img width="1146" alt="image" src="https://github.com/user-attachments/assets/2344368a-a2c7-4d25-b0a2-7180def41abf">


<img width="971" alt="image" src="https://github.com/user-attachments/assets/1f813da9-d362-4f1f-ba01-eb5df41d2889">

Explanation:
Requirement:

The solution must allow seamless encryption for S3 objects.
Users should not directly manage encryption keys.
Keys must be immediately deletable if necessary.
Why Option B is Correct:

AWS KMS allows importing key material into a customer managed CMK (Customer Master Key). This means you retain control over the key material.
If you need to immediately delete the key, you can use the DeleteImportedKeyMaterial API to remove the key material from AWS KMS. This action renders the key unusable instantly.
This approach meets the scalability and key management requirements, as AWS KMS handles the integration with S3 for seamless encryption.


<img width="915" alt="image" src="https://github.com/user-attachments/assets/685880af-3759-4d02-8d0c-7e7af343c7b0">
<img width="680" alt="image" src="https://github.com/user-attachments/assets/0d3f57bf-d937-48f5-88fe-5921834ff482">



<img width="927" alt="image" src="https://github.com/user-attachments/assets/29f4e84b-e0b3-4d26-a886-e6826a2b06cd">
Explanation:
Why Option A is Correct:
Operational Efficiency:

This solution allows the existing script to run successfully with the currently attached AWS managed IAM policies.
While the script runs, CloudTrail collects activity logs that show exactly which AWS services and actions are used.
IAM Access Analyzer can then generate a least privilege policy based on the collected logs, ensuring no unnecessary permissions are included.
Least Privilege Enforcement:

The IAM Access Analyzer uses the data from CloudTrail to construct a new, least privilege policy. This policy replaces the broad permissions provided by the AWS managed IAM policies.
Minimal Disruption:

The existing managed IAM policies remain attached during the analysis, ensuring the script functions correctly during the process.
Once the least privilege policy is created and tested, it can replace the managed IAM policies.



<img width="700" alt="image" src="https://github.com/user-attachments/assets/6681af4a-386c-41c0-8c5b-49e6adf771fc">
<img width="818" alt="image" src="https://github.com/user-attachments/assets/67a0aabf-a657-44ef-bca3-27bd8b62159c">



<img width="896" alt="image" src="https://github.com/user-attachments/assets/631e7750-0b13-4f75-bd74-69136b1d3ee2">
<img width="814" alt="image" src="https://github.com/user-attachments/assets/e9b127a9-1ea1-4e43-ad27-b334cc5bbf11">


<img width="1043" alt="image" src="https://github.com/user-attachments/assets/761d053a-5afc-4232-bd0d-bca8a822ff5d">
<img width="663" alt="image" src="https://github.com/user-attachments/assets/b251e907-514a-4b0e-abbd-01c94b356994">

<img width="925" alt="image" src="https://github.com/user-attachments/assets/3d95b424-9e0f-4b0c-bd41-65bb47c17580">
<img width="740" alt="image" src="https://github.com/user-attachments/assets/1afa3407-bcc7-4460-8453-ca474ca765ce">

<img width="899" alt="image" src="https://github.com/user-attachments/assets/832c6dfb-518d-4680-b52d-847a072c1e13">


<img width="967" alt="image" src="https://github.com/user-attachments/assets/45c1ffb4-4746-46f1-b2df-9af3920c5840">


<img width="956" alt="image" src="https://github.com/user-attachments/assets/baed3282-8169-45bd-94da-9700b3143d15">
<img width="697" alt="image" src="https://github.com/user-attachments/assets/ad152efa-7931-474d-ad43-5342b221f1b3">


<img width="962" alt="image" src="https://github.com/user-attachments/assets/d1f5c5c7-1352-49af-8fd4-bd9d6e001301">

<img width="955" alt="image" src="https://github.com/user-attachments/assets/a6dd0ce8-2aa2-45bd-aafc-63b71cc0e3e5">
<img width="729" alt="image" src="https://github.com/user-attachments/assets/069a6805-aafc-45a1-ab28-1b30ee212ff8">


<img width="927" alt="image" src="https://github.com/user-attachments/assets/cd985439-07c0-4da1-91a5-374a6169e86d">



<img width="968" alt="image" src="https://github.com/user-attachments/assets/540c43d5-af68-49b6-aa7e-edef7a6752a6">
<img width="792" alt="image" src="https://github.com/user-attachments/assets/0789b392-f044-42ed-9cf5-49f49c27db22">

<img width="901" alt="image" src="https://github.com/user-attachments/assets/eedc0013-10e7-4fd8-a56c-32ffefcf6714">


<img width="934" alt="image" src="https://github.com/user-attachments/assets/2570e24b-a917-4cb4-8a1e-24a99520e431">

<img width="900" alt="image" src="https://github.com/user-attachments/assets/f2f74373-e800-42e2-9443-cd0214c60d97">

<img width="898" alt="image" src="https://github.com/user-attachments/assets/094fb7cf-bb0a-4d85-a1f9-f658083aebf3">
<img width="703" alt="image" src="https://github.com/user-attachments/assets/d81858a7-837f-4b8d-ac1d-f614188d5047">


<img width="972" alt="image" src="https://github.com/user-attachments/assets/5e84a052-7730-4611-a568-aaae43c8938c">

<img width="937" alt="image" src="https://github.com/user-attachments/assets/275e2fef-2bbe-4cef-a0dd-576ef8d08e3f">


<img width="964" alt="image" src="https://github.com/user-attachments/assets/67caf9b5-d736-4896-a2e6-f19a63c1406c">


<img width="929" alt="image" src="https://github.com/user-attachments/assets/eb4475a6-f229-4285-a16e-825f265b6a84">



<img width="959" alt="image" src="https://github.com/user-attachments/assets/665ef715-635e-4de8-b577-bf391a6f1bf3">


<img width="903" alt="image" src="https://github.com/user-attachments/assets/c647e72c-55cc-4d97-a11c-b8706b8ccbcc">


<img width="994" alt="image" src="https://github.com/user-attachments/assets/e5735fbc-f323-412b-a6a0-32fe4d15b638">

<img width="937" alt="image" src="https://github.com/user-attachments/assets/376641be-66f6-4d20-a465-e5cbd1bd5168">

<img width="939" alt="image" src="https://github.com/user-attachments/assets/273f328c-412c-40d1-b59b-1f62e8608776">


<img width="900" alt="image" src="https://github.com/user-attachments/assets/aec46621-9518-44a8-aa0c-7879cb41f94b">

Answer: A and C

Explanation:

To assume a role in another account, two conditions must be met:

The calling role (LambdaAuditRole) must have permission to assume the target role (AcmeAuditFactoryRole).

This means the IAM policy attached to LambdaAuditRole must include the sts:AssumeRole action for the AcmeAuditFactoryRole. (Option A)
The trust policy on the target role (AcmeAuditFactoryRole) must allow the calling role (LambdaAuditRole) to assume it.

The trust policy of AcmeAuditFactoryRole must specify LambdaAuditRole as a trusted principal and allow the sts:AssumeRole action. (Option C)
When both these conditions are met, the LambdaAuditRole can successfully call sts:AssumeRole to assume AcmeAuditFactoryRole across AWS accounts.



<img width="943" alt="image" src="https://github.com/user-attachments/assets/b222f3ea-5d12-45f1-b91a-486f8bf1100f">
<img width="811" alt="image" src="https://github.com/user-attachments/assets/90dd4fd6-6bf7-4cc5-af45-d9940a0f5c0d">



<img width="1044" alt="image" src="https://github.com/user-attachments/assets/c7360670-d0bb-4795-bbc5-8af9a4601d93">



<img width="694" alt="image" src="https://github.com/user-attachments/assets/07ea9dca-d721-4b92-9816-dc3c079d6b45">
<img width="873" alt="image" src="https://github.com/user-attachments/assets/2b35a6e2-a42c-4a2c-b47d-760ab2e66f6f">


<img width="1169" alt="image" src="https://github.com/user-attachments/assets/73e24d03-21de-4e27-9aa4-994f6921b0af">


<img width="1205" alt="image" src="https://github.com/user-attachments/assets/fe73b121-5aed-44c7-ba0b-7fcc600bc586">

<img width="1140" alt="image" src="https://github.com/user-attachments/assets/baef3c28-0e74-4ddc-baa5-3ef39fb20f4a">

<img width="1130" alt="image" src="https://github.com/user-attachments/assets/ce81b5de-3093-4209-afba-a9b64009149c">

<img width="1120" alt="image" src="https://github.com/user-attachments/assets/ee9a737a-4066-4533-b6f0-dfe674747655">


<img width="1118" alt="image" src="https://github.com/user-attachments/assets/c84dd2c8-b1bb-46ef-90ea-1d07c69d7f30">

<img width="1134" alt="image" src="https://github.com/user-attachments/assets/c45b99a9-2aa8-4a55-849e-42c4bc6a3f96">


Q1. An application outputs logs to a text file. The logs must be continuously monitored for security incidents.Which design will meet the requirements with MINIMUM effort?
A. Create a scheduled process to copy the component's logs into Amazon S3.
Use S3 events to trigger a Lambda function that updates Amazon CloudWatch metrics with the log data. Set upCloudWatch alerts based on the metrics.
B. Install and configure the Amazon CloudWatch Logs agent on the application's EC2 instance.
Create a CloudWatch metric filter to monitor the application logs.
Set up CloudWatch alerts based on the metrics.
C. Create a scheduled process to copy the application log files to AWS CloudTrail.
Use S3 events to trigger Lambda functions that update CloudWatch metrics with the log data.
Set up CloudWatch alerts based on the metrics.
D. Create a file watcher that copies data to Amazon Kinesis when the application writes to the log file.
Have Kinesis trigger a Lambda function to update Amazon CloudWatch metrics with the log data.
Set up CloudWatch alerts based on the metrics.

Q2. The Security Engineer for a mobile game has to implement a method to authenticate users so that they cansave their progress. Because most of the users are part of the same OpenID- Connect compatible social mediawebsite, the Security Engineer would like to use that as the identity provider.
Which solution is the SIMPLEST way to allow the authentication of users using their social media identities?
A. Amazon Cognito
B. AssumeRoleWithWebIdentity API
C. Amazon Cloud Directory
D. Active Directory (AD) Connector




Q3. A Security Engineer has been asked to troubleshoot inbound connectivity to a web server. This single webserver is not receiving inbound connections from the internet, whereas all other web servers are functioningproperly.
The architecture includes network ACLs, security groups, and a virtual security appliance. In addition, theDevelopment team has implemented Application Load Balancers (ALBs) to distribute the load across all webservers. It is a requirement that traffic between the web servers and the internet flow through the virtual securityappliance.
The Security Engineer has verified the following:
1. The rule set in the Security Groups is correct
2. The rule set in the network ACLs is correct
3. The rule set in the virtual appliance is correct
Which of the following are other valid items to troubleshoot in this scenario? (Choose two.)
A. Verify that the 0.0.0.0/0 route in the route table for the web server subnet points to a NAT gateway.
B. Verify which Security Group is applied to the particular web server's elastic network interface (ENI).
C. Verify that the 0.0.0.0/0 route in the route table for the web server subnet points to the virtual securityappliance.
D. Verify the registered targets in the ALB.
E. Verify that the 0.0.0.0/0 route in the public subnet points to a NAT gateway.


Q4. Which approach will generate automated security alerts should too many unauthorized AWS API requests be identified?
A. Create an Amazon CloudWatch metric filter that looks for API call error codes and then implement an alarm based on that metric's rate.
B. Configure AWS CloudTrail to stream event data to Amazon Kinesis. Configure an AWS Lambda function on thestream to alarm when the threshold has been exceeded.
C. Run an Amazon Athena SQL query against CloudTrail log files. Use Amazon QuickSight to create anoperational dashboard.
D. Use the Amazon Personal Health Dashboard to monitor the account's use of AWS services, and raise an alertif service error rates increase.



Q5. A company has multiple production AWS accounts. Each account has AWS CloudTrail configured to log to asingle Amazon S3 bucket in a central account. Two of the production accounts have trails that are not logginganything to the S3 bucket.
Which steps should be taken to troubleshoot the issue? (Choose three.)
A. Verify that the log file prefix is set to the name of the S3 bucket where the logs should go.
B. Verify that the S3 bucket policy allows access for CloudTrail from the production AWS account IDs.
C. Create a new CloudTrail configuration in the account, and configure it to log to the account's S3 bucket.
D. Confirm in the CloudTrail Console that each trail is active and healthy.
E. Open the global CloudTrail configuration in the master account, and verify that the storage location is set to the correct S3 bucket.
F. Confirm in the CloudTrail Console that the S3 bucket name is set correctly.





Q6. Amazon CloudWatch Logs agent is successfully delivering logs to the CloudWatch Logs service. However,logs stop being delivered after the associated log stream has been active for a specific number of hours.What steps are necessary to identify the cause of this phenomenon? (Choose two.)
A. Ensure that file permissions for monitored files that allow the CloudWatch Logs agent to read the file have notbeen modified.
B. Verify that the OS Log rotation rules are compatible with the configuration requirements for agent streaming.
C. Configure an Amazon Kinesis producer to first put the logs into Amazon Kinesis Streams.
D. Create a CloudWatch Logs metric to isolate a value that changes at least once during the period before logging stops.
E. Use AWS CloudFormation to dynamically create and maintain the configuration file for the CloudWatch Logs agent.


Q7. A company has deployed a custom DNS server in AWS. The Security Engineer wants to ensure that Amazon EC2 instances cannot use the Amazon-provided DNS.
How can the Security Engineer block access to the Amazon-provided DNS in the VPC?

A. Deny access to the Amazon DNS IP within all security groups.
B. Add a rule to all network access control lists that deny access to the Amazon DNS IP.
C. Add a route to all route tables that black holes traffic to the Amazon DNS IP.
D. Disable DNS resolution within the VPC configuration.



Q8. An employee accidentally exposed an AWS access key and secret access key during a public presentation.The company Security Engineer immediately disabled the key.
How can the Engineer assess the impact of the key exposure and ensure that the credentials were not misused?(Choose two.)
A. Analyze AWS CloudTrail for activity.
B. Analyze Amazon CloudWatch Logs for activity.
C. Download and analyze the IAM Use report from AWS Trusted Advisor.
D. Analyze the resource inventory in AWS Config for IAM user activity.
E. Download and analyze a credential report from IAM.



Q9. Which of the following minimizes the potential attack surface for applications?
A. Use security groups to provide stateful firewalls for Amazon EC2 instances at the hypervisor level.
B. Use network ACLs to provide stateful firewalls at the VPC level to prevent access to any specific AWSresource.
C. Use AWS Direct Connect for secure trusted connections between EC2 instances within private subnets.D. Design network security in a single layer within the perimeter network (also known as DMZ, demilitarized zone,and screened subnet) to facilitate quicker responses to threats.



Q10 A distributed web application is installed across several EC2 instances in public subnets residing in twoAvailability Zones. Apache logs show several intermittent brute-force attacks from hundreds of IP addresses at thelayer 7 level over the past six months.
What would be the BEST way to reduce the potential impact of these attacks in the future?A. Use custom route tables to prevent malicious traffic from routing to the instances.
B. Update security groups to deny traffic from the originating source IP addresses.
C. Use network ACLs.
D. Install intrusion prevention software (IPS) on each instance.



Q11. A company plans to move most of its IT infrastructure to AWS. They want to leverage their existing onpremises Active Directory as an identity provider for AWS.
Which combination of steps should a Security Engineer take to federate the company's on- premises ActiveDirectory with AWS? (Choose two.)
A. Create IAM roles with permissions corresponding to each Active Directory group.
B. Create IAM groups with permissions corresponding to each Active Directory group.
C. Configure Amazon Cloud Directory to support a SAML provider.
D. Configure Active Directory to add relying party trust between Active Directory and AWS.
E. Configure Amazon Cognito to add relying party trust between Active Directory and AWS.



Q12. A security alert has been raised for an Amazon EC2 instance in a customer account that is exhibiting strangebehavior. The Security Engineer must first isolate the EC2 instance and then use tools for further investigation.What should the Security Engineer use to isolate and research this event? (Choose three.)
A. AWS CloudTrail
B. Amazon Athena
C. AWS Key Management Service (AWS KMS)
D. VPC Flow Logs
E. AWS Firewall Manager
F. Security groups



Q13 A financial institution has the following security requirements:
- Cloud-based users must be contained in a separate authentication domain.
- Cloud-based users cannot access on-premises systems.
As part of standing up a cloud environment, the financial institution is creating a number of Amazon manageddatabases and Amazon EC2 instances. An Active Directory service exists on- premises that has all theadministrator accounts, and these must be able to access the databases and instances.
How would the organization manage its resources in the MOST secure manner? (Choose two.)
A. Configure an AWS Managed Microsoft AD to manage the cloud resources.
B. Configure an additional on-premises Active Directory service to manage the cloud resources.
C. Establish a one-way trust relationship from the existing Active Directory to the new Active Directory service.
D. Establish a one-way trust relationship from the new Active Directory to the existing Active Directory service.
E. Establish a two-way trust between the new and existing Active Directory services.



Q14. An organization wants to be alerted when an unauthorized Amazon EC2 instance in its VPC performs a network port scan against other instances in the VPC. When the Security team performs its own internal tests in a separate account by using pre-approved third-party scanners from the AWS Marketplace, the Security team also then receives multiple Amazon GuardDuty events from Amazon CloudWatch alerting on its test activities.How can the Security team suppress alerts about authorized security tests while still receiving alerts about theunauthorized activity?
A. Use a filter in AWS CloudTrail to exclude the IP addresses of the Security team's EC2 instances.
B. Add the Elastic IP addresses of the Security team's EC2 instances to a trusted IP list in Amazon GuardDuty.
C. Install the Amazon Inspector agent on the EC2 instances that the Security team uses.
D. Grant the Security team's EC2 instances a role with permissions to call Amazon GuardDuty API operations



Q15. The Security team believes that a former employee may have gained unauthorized access to AWS resources sometime in the past 3 months by using an identified access key.
What approach would enable the Security team to find out what the former employee may have done within AWS?
A. Use the AWS CloudTrail console to search for user activity.
B. Use the Amazon CloudWatch Logs console to filter CloudTrail data by user.
C. Use AWS Config to see what actions were taken by the user.
D. Use Amazon Athena to query CloudTrail logs stored in Amazon S3.



Q16. The Security Engineer implemented a new vault lock policy for 10TB of data and called initiate- 12 hours ago.
The Audit team identified a typo that is allowing incorrect access to the vault-lock
What is the MOST cost-effective way to correct this?
A. Call the abort-vault-lock operation, fix the typo, and call the initiate-vault-lock again.
B. Copy the vault data to Amazon S3, delete the vault, and create a new vault with the data.
C. Update the policy, keeping the vault lock in place.
D. Update the policy and call initiate-vault-lock again to apply the new policy



Q17. A company wants to control access to its AWS resources by using identities and groups that are defined inits existing Microsoft Active Directory. What must the company create in its AWS account to map permissions forAWS services to Active Directory user attributes?
A. AWS IAM groups
B. AWS IAM users
C. AWS IAM roles
D. AWS IAM access keys


Q18. A company has contracted with a third party to audit several AWS accounts. To enable the audit, cross account IAM roles have been created in each account targeted for audit. The Auditor is having trouble accessing some of the accounts.
Which of the following may be causing this problem? (Choose three.)
A. The external ID used by the Auditor is missing or incorrect.
B. The Auditor is using the incorrect password.
C. The Auditor has not been granted sts:AssumeRole for the role in the destination account.
D. The Amazon EC2 role used by the Auditor must be set to the destination account role.
E. The secret key used by the Auditor is missing or incorrect.
F. The role ARN used by the Auditor is missing or incorrect




Q19 Compliance requirements state that all communications between company on-premises hosts and EC2instances be encrypted in transit. Hosts use custom proprietary protocols for their communication, and EC2instances need to be fronted by a load balancer for increased availability.
Which of the following solutions will meet these requirements?
A. Offload SSL termination onto an SSL listener on a Classic Load Balancer, and use a TCP connection between the load balancer and the EC2 instances.
B. Route all traffic throughout a TCP listener on a Classic Load Balancer, and terminate the TLS connection onthe EC2 instances.
C. Create an HTTPS listener using an Application Load Balancer, and route all of the communication through that load balancer.
D. Offload SSL termination onto an SSL listener using an Application Load Balancer, and re-spawn and SSLconnection between the load balancer and the EC2 instances.



Q20. An application is currently secured using network access control lists and security groups. Web servers arelocated in public subnets behind an Application Load Balancer (ALB); application servers are located in privatesubnets.
How can edge security be enhanced to safeguard the Amazon EC2 instances against attack? (Choose two.)
A. Configure the application's EC2 instances to use NAT gateways for all inbound traffic.
B. Move the web servers to private subnets without public IP addresses.
C. Configure AWS WAF to provide DDoS attack protection for the ALB.
D. Require all inbound network traffic to route through a bastion host in the private subnet.
E. Require all inbound and outbound network traffic to route through an AWS Direct Connect connection.




Q21. A Security Administrator is restricting the capabilities of company root user accounts. The company usesAWS Organizations and has enabled it for all feature sets, including consolidates billing. The top-level account isused for billing and administrative purposes, not for operational AWS resource purposes.
How can the Administrator restrict usage of member root user accounts across the organization?
A. Disable the use of the root user account at the organizational root. Enable multi-factor authentication of the rootuser account for each organizational member account.
B. Configure IAM user policies to restrict root account capabilities for each Organizations member account.
C. Create an organizational unit (OU) in Organizations with a service control policy that controls usage of the rootuser. Add all operational accounts to the new OU.
D. Configure AWS CloudTrail to integrate with Amazon CloudWatch Logs and then create a metric filter forRootAccountUsage.




Q22 A company has complex connectivity rules governing ingress, egress, and communications betweenAmazon EC2 instances. The rules are so complex that they cannot be implemented within the limits of themaximum number of security groups and network access control lists (network ACLs).
What mechanism will allow the company to implement all required network rules without incurring additional cost?
A. Configure AWS WAF rules to implement the required rules.
B. Use the operating system built-in, host-based firewall to implement the required rules.
C. Use a NAT gateway to control ingress and egress according to the requirements.
D. Launch an EC2-based firewall product from the AWS Marketplace, and implement the required rules in thatproduct.





Q23. A company requires that IP packet data be inspected for invalid or malicious content.
Which of the following approaches achieve this requirement? (Choose two.)
A. Configure a proxy solution on Amazon EC2 and route all outbound VPC traffic through it. Perform inspectionwithin proxy software on the EC2 instance.
B. Configure the host-based agent on each EC2 instance within the VPC. Perform inspection within thehost-based agent.
C. Enable VPC Flow Logs for all subnets in the VPC. Perform inspection from the Flow Log data within AmazonCloudWatch Logs.
D. Configure Elastic Load Balancing (ELB) access logs. Perform inspection from the log data within the ELBaccess log files.
E. Configure the CloudWatch Logs agent on each EC2 instance within the VPC. Perform inspection from the logdata within CloudWatch Logs.




Q24. A Security Engineer launches two Amazon EC2 instances in the same Amazon VPC but in separateAvailability Zones. Each instance has a public IP address and is able to connect to external hosts on the internet.The two instances are able to communicate with each other by using their private IP addresses, but they are notable to communicate with each other when using their public IP addresses.
Which action should the Security Engineer take to allow communication over the public IP addresses?
A. Associate the instances to the same security groups.
B. Add 0.0.0.0/0 to the egress rules of the instance security groups.
C. Add the instance IDs to the ingress rules of the instance security groups.
D. Add the public IP addresses to the ingress rules of the instance security groups.



Q25 The Security Engineer is managing a web application that processes highly sensitive personal information.The application runs on Amazon EC2. The application has strict compliance requirements, which instruct that allincoming traffic to the application is protected from common web exploits and that all outgoing traffic from the EC2instances is restricted to specific whitelisted URLs.
Which architecture should the Security Engineer use to meet these requirements?
A. Use AWS Shield to scan inbound traffic for web exploits. Use VPC Flow Logs and AWS Lambda to restrictegress traffic to specific whitelisted URLs.
B. Use AWS Shield to scan inbound traffic for web exploits. Use a third-party AWS Marketplace solution to restrictegress traffic to specific whitelisted URLs.
C. Use AWS WAF to scan inbound traffic for web exploits. Use VPC Flow Logs and AWS Lambda to restrictegress traffic to specific whitelisted URLs.
D. Use AWS WAF to scan inbound traffic for web exploits. Use a third-party AWS Marketplace solution to restrictegress traffic to specific whitelisted URLs.


Q26. A company recently experienced a DDoS attack that prevented its web server from serving content. Thewebsite is static and hosts only HTML, CSS, and PDF files that users download.
Based on the architecture shown in the image, what is the BEST way to protect the site against future attackswhile minimizing the ongoing operational overhead?
A. Move all the files to an Amazon S3 bucket. Have the web server serve the files from the S3 bucket.
B. Launch a second Amazon EC2 instance in a new subnet. Launch an Application Load Balancer in front of bothinstances.
C. Launch an Application Load Balancer in front of the EC2 instance. Create an Amazon CloudFront distribution infront of the Application Load Balancer.
D. Move all the files to an Amazon S3 bucket. Create a CloudFront distribution in front of the bucket and terminatethe web server.



Q27. The Information Technology department has stopped using Classic Load Balancers and switched toApplication Load Balancers to save costs. After the switch, some users on older devices are no longer able toconnect to the website.
What is causing this situation?
A. Application Load Balancers do not support older web browsers.
B. The Perfect Forward Secrecy settings are not configured correctly.
C. The intermediate certificate is installed within the Application Load Balancer.
D. The cipher suites on the Application Load Balancers are blocking connections.



Q28. A security team is responsible for reviewing AWS API call activity in the cloud environment for securityviolations. These events must be recorded and retained in a centralized location for both current and future AWSregions.
What is the SIMPLEST way to meet these requirements?
A. Enable AWS Trusted Advisor security checks in the AWS Console, and report all security incidents for allregions.
B. Enable AWS CloudTrail by creating individual trails for each region, and specify a single Amazon S3 bucket toreceive log files for later analysis.
C. Enable AWS CloudTrail by creating a new trail and applying the trail to all regions. Specify a single Amazon S3bucket as the storage location.
D. Enable Amazon CloudWatch logging for all AWS services across all regions, and aggregate them to a singleAmazon S3 bucket for later analysis.





Q29. A Security Administrator is performing a log analysis as a result of a suspected AWS account compromise.The Administrator wants to analyze suspicious AWS CloudTrail log files but is overwhelmed by the volume of auditlogs being generated.
What approach enables the Administrator to search through the logs MOST efficiently?
A. Implement a "write-only" CloudTrail event filter to detect any modifications to the AWS account resources.
B. Configure Amazon Macie to classify and discover sensitive data in the Amazon S3 bucket that contains theCloudTrail audit logs.
C. Configure Amazon Athena to read from the CloudTrail S3 bucket and query the logs to examine accountactivities.
D. Enable Amazon S3 event notifications




Q30. A Systems Engineer has been tasked with configuring outbound mail through Simple Email Service (SES)and requires compliance with current TLS standards.
The mail application should be configured to connect to which of the following endpoints and correspondingports?
A. email.us-east-1.amazonaws.com over port 8080
B. email-pop3.us-east-1.amazonaws.com over port 995
C. email-smtp.us-east-1.amazonaws.com over port 587
D. email-imap.us-east-1.amazonaws.com over port 993




Q31. A water utility company uses a number of Amazon EC2 instances to manage updates to a fleet of 2,000Internet of Things (IoT) field devices that monitor water quality. These devices each have unique accesscredentials.
An operational safety policy requires that access to specific credentials is independently auditable.
What is the MOST cost-effective way to manage the storage of credentials?
A. Use AWS Systems Manager to store the credentials as Secure Strings Parameters.
Secure by using an AWS KMS key.
B. Use AWS Key Management System to store a master key, which is used to encrypt the credentials.
The encrypted credentials are stored in an Amazon RDS instance.
C. Use AWS Secrets Manager to store the credentials.
D. Store the credentials in a JSON file on Amazon S3 with server-side encryption.




<img width="1109" alt="image" src="https://github.com/user-attachments/assets/0efa1113-eb0c-4e56-9b80-047c579a0abc">
What additional items need to be added to the IAM user policy? (Choose two.)
A. kms:GenerateDataKey
B. kms:Decrypt
C. kms:CreateGrant
D. "Condition": {
"Bool": {
"kms:ViaService": "ec2.us-west-2.amazonaws.com"
}
}
E. "Condition": {
"Bool": {
"kms:GrantIsForAWSResource": true
}
}


Q33. A Security Administrator has a website hosted in Amazon S3. The Administrator has been given the followingrequirements:
Users may access the website by using an Amazon CloudFront distribution. Users may not access the websitedirectly by using an Amazon S3 URL.
Which configurations will support these requirements? (Choose two.)
A. Associate an origin access identity with the CloudFront distribution.
B. Implement a "Principal": "cloudfront.amazonaws.com" condition in the S3 bucket policy.
C. Modify the S3 bucket permissions so that only the origin access identity can access the bucket contents.
D. Implement security groups so that the S3 bucket can be accessed only by using the intended CloudFrontdistribution.
E. Configure the S3 bucket policy so that it is accessible only through VPC endpoints, and place the CloudFrontdistribution into the specified VPC



<img width="1038" alt="image" src="https://github.com/user-attachments/assets/0bf090e2-484a-496a-99da-897f377510dd">
A. The Lambda function does not have permissions to start the Athena query execution.
B. The Security Engineer does not have permissions to start the Athena query execution.
C. The Athena service does not support invocation through Lambda.
D. The Lambda function does not have permissions to access the CloudTrail S3 bucket.



Q35. Your company has multiple accounts in various regions which contains resources such as EC2, CloudWatch,DynamoDB, EBS, Redshift, RDS , S3, ElasticbeanStalk, IAM , Autoscaling and ElasticloadBalancer. The IT Auditdepartment requires a compliance report of all the resources that are used by your company.
Which of the following will help you to provide a report in the easiest way?
A. Create a powershell script using the AWS CLI. Query for all resources with the tag of production.
B. Create a bash shell script with the AWS CLI. Query for all resources in all regions. Store the results in an S3bucket.
C. Use Cloud Trail to get the list of all resources
D. Use AWS Config to get the list of all resources



Q36. A Lambda function reads metadata from an S3 object and stores the metadata in a DynamoDB table. Thefunction is triggered whenever an object is stored within the S3 bucket. How should the Lambda function be givenaccess to the DynamoDB table?
A. Create a VPC endpoint for DynamoDB within a VPC. Configure the Lambda function to access resources in theVPC.
B. Create a resource policy that grants the Lambda function permissions to write to the DynamoDB table. Attachthe policy to the DynamoDB table.
C. Create an I AM user with permissions to write to the DynamoDB table. Store an access key for that user in theLambda environment variables.
D. Create an I AM service role with permissions to write to the DynamoDB table. Associate that role with theLambda function



Q37. Your company has defined privileged users for their AWS Account. These users are administrators for keyresources defined in the company. There is now a mandate to enhance the security authentication for these users.How can this be accomplished?
A. Enable MFA for these user accounts
B. Enable versioning for these user accounts
C. Enable accidental deletion for these user accounts
D. Disable root access for the users


Q38. An application running on EC2 instances must use a username and password to access a database. Thedeveloper has stored those secrets in the SSM Parameter Store with type SecureString using the default KMSCMK.
Which combination of configuration steps will allow the application to access the secrets via the API? Select 2answers from the options below
A. Add the EC2 instance role as a trusted service to the SSM service role.
B. Add permission to use the KMS key to decrypt to the SSM service role.
C. Add permission to read the SSM parameter to the EC2 instance role.
D. Add permission to use the KMS key to decrypt to the EC2 instance role.
E. Add the SSM service role as a trusted service to the EC2 instance role.



Q39. Your application currently uses customer keys which are generated via AWS KMS in the US east region. Younow want to use the same set of keys from the EU-Central region.
How can this be accomplished?
A. Export the key from the US east region and import them into the EU-Central region
B. Use key rotation and rotate the existing keys to the EU-Central region
C. Use the backing key from the US east region and use it in the EU-Central region
D. This is not possible since keys from KMS are region specific



Q40. You have a set of Customer keys created using the AWS KMS service. These keys have been used foraround 6 months.
features for the existing set of key's but are not able to You are now trying to use the new KMS do so.
What could be the reason for this?
A. You have not explicitly given access via the key policy
B. You have not explicitly given access via the bucket policy
C. You have not given access via the I AM roles X
D. You have not explicitly given access via I AM users



Q41. A security team must present a daily briefing to the CISO that includes a report of which of the company's thousands of EC2 instances and on-premises servers are missing the latest security patches. All instances/servers must be brought into compliance within 24 hours so they do not show up on the next day's report.
How can the security team fulfill these requirements?
A. Use Amazon QuickSight and Cloud Trail to generate the report of out of compliance instances/servers.Redeploy all out of compliance instances/servers using an AMI with the latest patches.
B. Use Systems Manager Patch Manager to generate the report of out of compliance instances/ servers. Use Systems Manager Patch Manager to install the missing patches.
C. Use Systems Manager Patch Manager to generate the report of out of compliance instances/ servers.Redeploy all out of compliance instances/servers using an AMI with the latest patches.
D. Use Trusted Advisor to generate the report of out of compliance instances/ servers. Use Systems ManagerPatch Manager to install the missing patches



Q42. A company's database developer has just migrated an Amazon RDS database credential to be stored andmanaged by AWS Secrets Manager. 
The developer has also enabled rotation of the credential within the SecretsManager console and set the rotation to change every 30 days.
After a short period of time, a number of existing applications have failed with authentication errors.
What is the MOST likely cause of the authentication errors?
A. Migrating the credential to RDS requires that all access come through requests to the Secrets Manager.
B. Enabling rotation in Secrets Manager causes the secret to rotate immediately and the applications are using the earlier credential.
C. The Secrets Manager IAM policy does not allow access to the RDS database.
D. The Secrets Manager IAM policy does not allow access for the applications.


Q43. You want to get a list of vulnerabilities for an EC2 Instance as per the guidelines set by the Center of InternetSecurity. How can you go about doing this?
A. Enable AWS Guard Duty for the Instance
B. Use AWS Trusted Advisor
C. Use AWS Inspector
D. Use AWS Macie 

Q44. You have an instance setup in a test environment in AWS. You installed the required application and thepromoted the server to a production environment. Your IT Security team has advised that there maybe trafficflowing in from an unknown IP address to port 22.
How can this be mitigated immediately?
A. Shutdown the instance
B. Remove the rule for incoming traffic on port 22 for the Security Group
C. Change the AMI for the instance
D. Change the Instance type for the Instance



Q45. Your company has defined a number of EC2 Instances. They want to know if any of the security groups allow unrestricted access to a resource.
Which of the following provides the SIMPLEST solution to accomplish the requirement?
A. Use AWS Inspector to inspect all the security Groups
B. Use the AWS Trusted Advisor to see which security groups have compromised access.
C. Use AWS Config to see which security groups have compromised access.
D. Use the AWS CLI to query the security groups and then filter for the rules which have unrestricted access



Q46. A company is using CloudTrail to log all AWS API activity for all regions in all of its accounts. The CISO hasasked that additional steps be taken to protect the integrity of the log files. What combination of steps will protectthe log files from intentional or unintentional alteration? Choose 2 answers from the options given below
A. Create an S3 bucket in a dedicated log account and grant the other accounts write only access. Deliver all log files from every account to this S3 bucket.
B. Write a Lambda function that queries the Trusted Advisor Cloud Trail checks. Run the function every 10minutes.
C. Enable Cloud Trail log file integrity validation
D. Use Systems Manager Configuration Compliance to continually monitor the access policies of S3 bucketscontaining Cloud Trail logs.
E. Create a Security Group that blocks all traffic except calls from the CloudTrail service. Associate the securitygroup with all the Cloud Trail destination S3 buckets.




Q47. A security team is creating a response plan in the event an employee executes unauthorized actions on AWS infrastructure.
They want to include steps to determine if the employee’s IAM permissions changed as part of
the incident.
What steps should the team document in the plan?
A. Use AWS Config to examine the employee’s IAM permissions prior to the incident and compare them to the employee’s current IAM permissions.
B. Use Macie to examine the employee’s IAM permissions prior to the incident and compare them to th eemployee’s current IAM permissions.
C. Use CloudTrail to examine the employee’s IAM permissions prior to the incident and compare them to the employee’s current IAM permissions.
D. Use Trusted Advisor to examine the employee’s IAM permissions prior to the incident and compare them to the employee's current IAM permissions.




Q48. During a recent internal investigation, it was discovered that all API logging was disabled in a production account, and the root user had created new API keys that appear to have been used several times.
What could have been done to detect and automatically remediate the incident?
A. Using Amazon Inspector, review all of the API calls and configure the inspector agent to leverage SNS topics tonotify security of the change to AWS CloudTrail, and revoke the new API keys for the root user.
B. Using AWS Config, create a config rule that detects when AWS CloudTrail is disabled, as well as any calls tothe root user create-api-key. Then use a Lambda function to re-enable CloudTrail logs and deactivate the root API keys.
C. Using Amazon CloudWatch, create a CloudWatch event that detects AWS CloudTrail deactivation and aseparate Amazon Trusted Advisor check to automatically detect the creation of root API keys. Then use a Lambda function to enable AWS CloudTrail and deactivate the root API keys.
D. Using Amazon CloudTrail, create a new CloudTrail event that detects the deactivation of CloudTrail logs, and a separate CloudTrail event that detects the creation of root API keys. Then use a Lambda function to enable CloudTrail and deactivate the root API keys.



Q49. An application has a requirement to be resilient across not only Availability Zones within the application'sprimary region but also be available within another region altogether.
Which of the following supports this requirement for AWS resources that are encrypted by AWS KMS?
A. Copy the application's AWS KMS CMK from the source region to the target region so that it can be used to decrypt the resource after it is copied to the target region.
B. Configure AWS KMS to automatically synchronize the CMK between regions so that it can be used to decryptthe resource in the target region.
C. Use AWS services that replicate data across regions, and re-wrap the data encryption key created in the source region by using the CMK in the target region so that the target region's CMK can decrypt the database encryption key.
D. Configure the target region's AWS service to communicate with the source region's AWS KMS so that it can decrypt the resource in the target region.


Q50. An organization policy states that all encryption keys must be automatically rotated every 12 months.Which AWS Key Management Service (KMS) key type should be used to meet this requirement?
A. AWS managed Customer Master Key (CMK)
B. Customer managed CMK with AWS generated key material
C. Customer managed CMK with imported key material
D. AWS managed data key



Q51. A Security Engineer received an AWS Abuse Notice listing EC2 instance IDs that are reportedly abusingother hosts.
Which action should the Engineer take based on this situation? (Choose three.)
A. Use AWS Artifact to capture an exact image of the state of each instance.
B. Create EBS Snapshots of each of the volumes attached to the compromised instances.
C. Capture a memory dump.
D. Log in to each instance with administrative credentials to restart the instance.
E. Revoke all network ingress and egress except for to/from a forensics.
F. Run Auto Recovery for Amazon EC2.



Q52. A Security Administrator is configuring an Amazon S3 bucket and must meet the following securityrequirements:
- Encryption in transit
- Encryption at rest
- Logging of all object retrievals in AWS CloudTrail
Which of the following meet these security requirements? (Choose three.)
A. Specify "aws:SecureTransport": "true" within a condition in the S3 bucket policy.
B. Enable a security group for the S3 bucket that allows port 443, but not port 80.
C. Set up default encryption for the S3 bucket.
D. Enable Amazon CloudWatch Logs for the AWS account.
E. Enable API logging of data events for all S3 objects.
F. Enable S3 object versioning for the S3 bucket.



Q53 What is the function of the following AWS Key Management Service (KMS) key policy attached to acustomer master key (CMK)?
<img width="784" alt="image" src="https://github.com/user-attachments/assets/5f51affe-80b9-4213-8dbe-ba742375299e">




Q54
<img width="804" alt="image" src="https://github.com/user-attachments/assets/6cff2283-3f55-411a-8826-f4f65978afe9">


Q55 A threat assessment has identified a risk whereby an internal employee could exfiltrate sensitive data fromproduction host running inside AWS (Account 1). The threat was documented as follows:
Threat description: A malicious actor could upload sensitive data from Server X by configuring credentials for anAWS account (Account 2) they control and uploading data to an Amazon S3 bucket within their control. Server X has outbound internet access configured via a proxy server. Legitimate access to S3 is required so thatthe application can upload encrypted files to an S3 bucket. Server X is currently using an IAM instance role. Theproxy server is not able to inspect any of the server communication due to TLS encryption.

Which of the following options will mitigate the threat? (Choose two.)
A. Bypass the proxy and use an S3 VPC endpoint with a policy that whitelists only certain S3 buckets withinAccount 1.
B. Block outbound access to public S3 endpoints on the proxy server.
C. Configure Network ACLs on Server X to deny access to S3 endpoints.
D. Modify the S3 bucket policy for the legitimate bucket to allow access only from the public IP addressesassociated with the application server.
E. Remove the IAM instance role from the application server and save API access keys in a trusted and encryptedapplication config file.





Q56. A company will store sensitive documents in three Amazon S3 buckets based on a data classificationscheme of "Sensitive," "Confidential," and "Restricted." The security solution must meet all of the followingrequirements:
Each object must be encrypted using a unique key.
Items that are stored in the "Restricted" bucket require two-factor authentication for decryption. AWS KMS must automatically rotate encryption keys annually.
Which of the following meets these requirements?
A. Create a Customer Master Key (CMK) for each data classification type, and enable the rotation of it annually.For the "Restricted" CMK, define the MFA policy within the key policy. Use S3 SSE- KMS to encrypt the objects.
B. Create a CMK grant for each data classification type with EnableKeyRotation and MultiFactorAuthPresent setto true. S3 can then use the grants to encrypt each object with a unique CMK.
C. Create a CMK for each data classification type, and within the CMK policy, enable rotation of it annually, anddefine the MFA policy. S3 can then create DEK grants to uniquely encrypt each object within the S3 bucket.
D. Create a CMK with unique imported key material for each data classification type, and rotate them annually.For the "Restricted" key material, define the MFA policy in the key policy. Use S3 SSE-KMS to encrypt the objects



An organization wants to deploy a three-tier web application whereby the application servers run on AmazonEC2 instances. These EC2 instances need access to credentials that they will use to authenticate their SQLconnections to an Amazon RDS DB instance. Also, AWS Lambda functions must issue queries to the RDSdatabase by using the same database credentials.
The credentials must be stored so that the EC2 instances and the Lambda functions can access them. No otheraccess is allowed. The access logs must record when the credentials were accessed and by whom.
What should the Security Engineer do to meet these requirements?
A. Store the database credentials in AWS Key Management Service (AWS KMS). Create an IAM role with accessto AWS KMS by using the EC2 and Lambda service principals in the role's trust policy. Add the role to an EC2instance profile. Attach the instance profile to the EC2 instances.
Set up Lambda to use the new role for execution.
B. Store the database credentials in AWS KMS. Create an IAM role with access to KMS by using the EC2 andLambda service principals in the role's trust policy. Add the role to an EC2 instance profile. Attach the instanceprofile to the EC2 instances and the Lambda function.
C. Store the database credentials in AWS Secrets Manager. Create an IAM role with access to Secrets Managerby using the EC2 and Lambda service principals in the role's trust policy. Add the role to an EC2 instance profile.Attach the instance profile to the EC2 instances and the Lambda function.
D. Store the database credentials in AWS Secrets Manager. Create an IAM role with access to Secrets Managerby using the EC2 and Lambda service principals in the role's trust policy. Add the role to an EC2 instance profile.Attach the instance profile to the EC2 instances. Set up Lambda to use the new role for execution.




Q58. An organization is using Amazon CloudWatch Logs with agents deployed on its Linux Amazon EC2 instances. The agent configuration files have been checked and the application log files to be pushed are configured correctly. A review has identified that logging from specific instances is missing.
Which steps should be taken to troubleshoot the issue? (Choose two.)
A. Use an EC2 run command to confirm that the "awslogs" service is running on all instances.
B. Verify that the permissions used by the agent allow creation of log groups/streams and to put log events.
C. Check whether any application log entries were rejected because of invalid time stamps by reviewing /var/cwlogs/rejects.log.
D. Check that the trust relationship grants the service "cwlogs.amazonaws.com" permission to write objects to the Amazon S3 staging bucket.
E. Verify that the time zone on the application servers is in UTC.



A. The Amazon WorkMail and Amazon SES services have delegated KMS encrypt and delegated KMS encryptand decrypt permissions to the ExampleUser principal in the 111122223333 account.
B. The ExampleUser principal can transparently encrypt and decrypt email exchanges specifically betweenExampleUser and AWS.
C. The CMK is to be used for encrypting and decrypting only when the principal is ExampleUser and the requestcomes from WorkMail or SES in the specified region.
D. The key policy allows WorkMail or SES to encrypt or decrypt on behalf of the user for any CMK in the account.



<img width="1049" alt="image" src="https://github.com/user-attachments/assets/cfa44caf-7543-45f9-ad45-14b15bb174eb">


A security engineer must use AWS Key Management Service (AWS KMS) to design a key management solution for a set of Amazon Elastic Block Store (Amazon
EBS) volumes that contain sensitive data. The solution needs to ensure that the key material automatically expires in 90 days.
Which solution meets these criteria?

A. A customer managed CMK that uses customer provided key material
B. A customer managed CMK that uses AWS provided key material
C. An AWS managed CMK
D. Operation system-native encryption that uses GnuPG



<img width="1009" alt="image" src="https://github.com/user-attachments/assets/fa3d17f3-3735-4934-8bd3-eb10ba586888">



<img width="1126" alt="image" src="https://github.com/user-attachments/assets/1bc76a3d-9de7-4164-b465-46c4b6d7dd3c">


Q527. A company stores images for a website in an Amazon S3 bucket. The company is using Amazon CloudFront to serve the images to end users. The company recently discovered that the images are being accessed from countries where the company does not have a distribution license. Which actions should the company take to secure the images to limit their distribution? (Select TWO.)
A. Update the S3 bucket policy to restrict access to a CloudFront origin access identity (OAI).
B. Update the website DNS record to use an Amazon Route 53 geolocation record deny list of countries where the company lacks a license
C. Add a CloudFront georestriction deny list of countries where the company lacks a license.
D. Update the S3 bucket policy with a deny list of countries where the company lacks a license.
E. Enable the Restrict Viewer Access option in CloudFront to create a deny list of countries where the company lacks a license




<img width="1037" alt="image" src="https://github.com/user-attachments/assets/91a2288b-7c0c-4ebd-9095-9bf7e4d7e044">


<img width="1059" alt="image" src="https://github.com/user-attachments/assets/c4f597e0-945e-4ba1-b92a-61fd752bf948">
<img width="1144" alt="image" src="https://github.com/user-attachments/assets/a1991c45-bdee-4c9d-a267-253657cfc9e9">
<img width="1108" alt="image" src="https://github.com/user-attachments/assets/c2315f78-6347-451e-8037-45ae2ce17fbf">




<img width="1048" alt="image" src="https://github.com/user-attachments/assets/039813bb-e87b-41d7-9b9b-fe6d142dfe3b">

<img width="963" alt="image" src="https://github.com/user-attachments/assets/70eecb6a-8740-488b-837b-0e8a6a8cc08b">



A company is expanding its group of stores. On the day that each new store opens, the company wants to launch a customized web application for that store. Each store's application will have a non-production environment and a production environment. Each environment will be deployed in a separate AWS account. The company uses AWS Organizations and has an OU that is used only for these accounts. 
The company distributes most of the development work to third-party development teams. A security engineer needs to ensure that each team follows the company's deployment plan for AWS resources. The security engineer also must limit access to the deployment plan to only the developers who need access. The security engineer already has created an AWS CloudFormation template that implements the deployment plan.
What should the security engineer do next to meet the requirements in the MOST secure way? A or C

A. Create an AWS Service Catalog portfolio in the organization's management account. Upload the CloudFormation template. Add the template to the portfolio's product list. Share the portfolio with the OU.
B. Use the CloudFormation CLI to create a module from the CloudFormation template. Register the module as a private extension in the CloudFormation registry. Publish the extension. In the OU, create an SCP that allows access to the extension.
C. Create an AWS Service Catalog portfolio in the organization's management account. Upload the CloudFormation template. Add the template to the portfolio's product list. Create an IAM role that has a trust policy that allows cross-account access to the portfolio for users in the OU accounts. Attach the AWSServiceCatalogEndUserFullAccess managed policy to the role.
D. Use the CloudFormation CLI to create a module from the CloudFormation template. Register the module as a private extension in the CloudFormation registry. Publish the extension. Share the extension with the OU.




A company uses AWS Signer with all of the company’s AWS Lambda functions. A developer recently stopped working for the company. The company wants to ensure that all the code that the developer wrote can no longer be deployed to the Lambda functions.

Which solution will meet this requirement?  A

A. Revoke all versions of the signing profile assigned to the developer.
B. Examine the developer’s IAM roles. Remove all permissions that grant access to Signer.
C. Re-encrypt all source code with a new AWS Key Management Service (AWS KMS) key.
D. Use Amazon CodeGuru to profile all the code that the Lambda functions use.


 
An IAM user receives an Access Denied message when the user attempts to access objects in an Amazon S3 bucket. The user and the S3 bucket are in the same AWS account. The S3 bucket is configured to use server-side encryption with AWS KMS keys (SSE-KMS) to encrypt all of its objects at rest by using a customer managed key from the same AWS account. The S3 bucket has no bucket policy defined. The IAM user has been granted permissions through an IAM policy that allows the kms:Decrypt permission to the customer managed key. The IAM policy also allows the s3:List* and s3:Get* permissions for the S3 bucket and its objects.

Which of the following is a possible reason that the IAM user cannot access the objects in the S3 bucket?  D

A. The IAM policy needs to allow the kms:DescribeKey permission.
B. The S3 bucket has been changed to use the AWS managed key to encrypt objects at rest.
C. An S3 bucket policy needs to be added to allow the IAM user to access the objects.
D. The KMS key policy has been edited to remove the ability for the AWS account to have full access to the key.  





A company uses AWS Organizations to manage a multi-account AWS environment in a single AWS Region. The organization's management account is named management-01. The company has turned on AWS Config in all accounts in the organization. The company has designated an account named security-01 as the delegated administrator for AWS Config.
All accounts report the compliance status of each account's rules to the AWS Config delegated administrator account by using an AWS Config aggregator. Each account administrator can configure and manage the account's own AWS Config rules to handle each account's unique compliance requirements.
A security engineer needs to implement a solution to automatically deploy a set of 10 AWS Config rules to all existing and future AWS accounts in the organization. The solution must turn on AWS Config automatically during account creation.
Which combination of steps will meet these requirements? (Choose two.)  BE

A. Create an AWS CloudFormation template that contains the 10 required AWS Config rules. Deploy the template by using CloudFormation StackSets in the security-01 account.
B. Create a conformance pack that contains the 10 required AWS Config rules. Deploy the conformance pack from the security-01 account.
C. Create a conformance pack that contains the 10 required AWS Config rules. Deploy the conformance pack from the management-01 account.
D. Create an AWS CloudFormation template that will activate AWS Config. Deploy the template by using CloudFormation StackSets in the security-01 account.
E. Create an AWS CloudFormation template that will activate AWS Config. Deploy the template by using CloudFormation StackSets in the management-01 account.





A company is using Amazon Elastic Container Service (Amazon ECS) to run its container-based application on AWS. The company needs to ensure that the container images contain no severe vulnerabilities. The company also must ensure that only specific IAM roles and specific AWS accounts can access the container images.

Which solution will meet these requirements with the LEAST management overhead?   C 

A. Pull images from the public container registry. Publish the images to Amazon Elastic Container Registry (Amazon ECR) repositories with scan on push configured in a centralized AWS account. Use a CI/CD pipeline to deploy the images to different AWS accounts. Use identity-based policies to restrict access to which IAM principals can access the images.
B. Pull images from the public container registry. Publish the images to a private container registry that is hosted on Amazon EC2 instances in a centralized AWS account. Deploy host-based container scanning tools to EC2 instances that run Amazon ECS. Restrict access to the container images by using basic authentication over HTTPS.
C. Pull images from the public container registry. Publish the images to Amazon Elastic Container Registry (Amazon ECR) repositories with scan on push configured in a centralized AWS account. Use a CI/CD pipeline to deploy the images to different AWS accounts. Use repository policies and identity-based policies to restrict access to which IAM principals and accounts can access the images.
D. Pull images from the public container registry. Publish the images to AWS CodeArtifact repositories in a centralized AWS account. Use a CI/CD pipeline to deploy the images to different AWS accounts. Use repository policies and identity-based policies to restrict access to which IAM principals and accounts can access the images. 

<img width="808" alt="image" src="https://github.com/user-attachments/assets/7cf9f903-85e1-44ab-b100-d9d2fda1c6c4">





A company has several petabytes of data. The company must preserve this data for 7 years to comply with regulatory requirements. The company's compliance team asks a security officer to develop a strategy that will prevent anyone from changing or deleting the data.
Which solution will meet this requirement MOST cost-effectively?  A or C 

A. Create an Amazon S3 bucket. Configure the bucket to use S3 Object Lock in compliance mode. Upload the data to the bucket. Create a resource-based bucket policy that meets all the regulatory requirements.
B. Create an Amazon S3 bucket. Configure the bucket to use S3 Object Lock in governance mode. Upload the data to the bucket. Create a user-based IAM policy that meets all the regulatory requirements.
C. Create a vault in Amazon S3 Glacier. Create a Vault Lock policy in S3 Glacier that meets all the regulatory requirements. Upload the data to the vault.
D. Create an Amazon S3 bucket. Upload the data to the bucket. Use a lifecycle rule to transition the data to a vault in S3 Glacier. Create a Vault Lock policy that meets all the regulatory requirements.

<img width="788" alt="image" src="https://github.com/user-attachments/assets/212a98fa-b42b-48a5-9e57-1ea191443cbb">
<img width="1086" alt="image" src="https://github.com/user-attachments/assets/9248384b-c5dd-439a-bba9-8cd3665a385c">




Company A has an AWS account that is named Account A. Company A recently acquired Company B, which has an AWS account that is named Account B. Company B stores its files in an Amazon S3 bucket. The administrators need to give a user from Account A full access to the S3 bucket in Account B.

After the administrators adjust the IAM permissions for the user in Account A to access the S3 bucket in Account B, the user still cannot access any files in the S3 bucket.

Which solution will resolve this issue?  C 

A. In Account B, create a bucket ACL to allow the user from Account A to access the S3 bucket in Account B.
B. In Account B, create an object ACL to allow the user from Account A to access all the objects in the S3 bucket in Account B.
C. In Account B, create a bucket policy to allow the user from Account A to access the S3 bucket in Account B.
D. In Account B, create a user policy to allow the user from Account A to access the S3 bucket in Account B.




A company has an AWS Lambda function that creates image thumbnails from larger images. The Lambda function needs read and write access to an Amazon S3 bucket in the same AWS account.
Which solutions will provide the Lambda function this access? (Choose two.)。 C/D 

A. Create an IAM user that has only programmatic access. Create a new access key pair. Add environmental variables to the Lambda function with the access key ID and secret access key. Modify the Lambda function to use the environmental variables at run time during communication with Amazon S3.
B. Generate an Amazon EC2 key pair. Store the private key in AWS Secrets Manager. Modify the Lambda function to retrieve the private key from Secrets Manager and to use the private key during communication with Amazon S3.
C. Create an IAM role for the Lambda function. Attach an IAM policy that allows access to the S3 bucket.
D. Create an IAM role for the Lambda function. Attach a bucket policy to the S3 bucket to allow access. Specify the function's IAM role as the principal.
E. Create a security group. Attach the security group to the Lambda function. Attach a bucket policy that allows access to the S3 bucket through the security group ID.



A company needs a security engineer to implement a scalable solution for multi-account authentication and authorization. The solution should not introduce additional user-managed architectural components. Native AWS features should be used as much as possible. The security engineer has set up AWS Organizations with all features activated and AWS IAM Identity Center (AWS Single Sign-On) enabled.
Which additional steps should the security engineer take to complete the task?  B 

A. Use AD Connector to create users and groups for all employees that require access to AWS accounts. Assign AD Connector groups to AWS accounts and link to the IAM roles in accordance with the employees’ job functions and access requirements. Instruct employees to access AWS accounts by using the AWS Directory Service user portal.
B. Use an IAM Identity Center default directory to create users and groups for all employees that require access to AWS accounts. Assign groups to AWS accounts and link to permission sets in accordance with the employees’ job functions and access requirements. Instruct employees to access AWS accounts by using the IAM Identity Center user portal.
C. Use an IAM Identity Center default directory to create users and groups for all employees that require access to AWS accounts. Link IAM Identity Center groups to the IAM users present in all accounts to inherit existing permissions. Instruct employees to access AWS accounts by using the IAM Identity Center user portal.
D. Use AWS Directory Service for Microsoft Active Directory to create users and groups for all employees that require access to AWS accounts. Enable AWS Management Console access in the created directory and specify IAM Identity Center as a source of information for integrated accounts and permission sets. Instruct employees to access AWS accounts by using the AWS Directory Service user portal.



A company has deployed Amazon GuardDuty and now wants to implement automation for potential threats. The company has decided to start with RDP brute force attacks that come from Amazon EC2 instances in the company's AWS environment. A security engineer needs to implement a solution that blocks the detected communication from a suspicious instance until investigation and potential remediation can occur.
Which solution will meet these requirements?   C

A. Configure GuardDuty to send the event to an Amazon Kinesis data stream. Process the event with an Amazon Kinesis Data Analytics for Apache Flink application that sends a notification to the company through Amazon Simple Notification Service (Amazon SNS). Add rules to the network ACL to block traffic to and from the suspicious instance.
B. Configure GuardDuty to send the event to Amazon EventBridge. Deploy an AWS WAF web ACL. Process the event with an AWS Lambda function that sends a notification to the company through Amazon Simple Notification Service (Amazon SNS) and adds a web ACL rule to block traffic to and from the suspicious instance.
C. Enable AWS Security Hub to ingest GuardDuty findings and send the event to Amazon EventBridge. Deploy AWS Network Firewall. Process the event with an AWS Lambda function that adds a rule to a Network Firewall firewall policy to block traffic to and from the suspicious instance.
D. Enable AWS Security Hub to ingest GuardDuty findings. Configure an Amazon Kinesis data stream as an event destination for Security Hub. Process the event with an AWS Lambda function that replaces the security group of the suspicious instance with a security group that does not allow any connections.






A company has an AWS account that hosts a production application. The company receives an email notification that Amazon GuardDuty has detected an Impact:IAMUser/AnomalousBehavior finding in the account. A security engineer needs to run the investigation playbook for this security incident and must collect and analyze the information without affecting the application.
Which solution will meet these requirements MOST quickly?   B 

A. Log in to the AWS account by using read-only credentials. Review the GuardDuty finding for details about the IAM credentials that were used. Use the IAM console to add a DenyAll policy to the IAM principal.
B. Log in to the AWS account by using read-only credentials. Review the GuardDuty finding to determine which API calls initiated the finding. Use Amazon Detective to review the API calls in context.
C. Log in to the AWS account by using administrator credentials. Review the GuardDuty finding for details about the IAM credentials that were used. Use the IAM console to add a DenyAll policy to the IAM principal.
D. Log in to the AWS account by using read-only credentials. Review the GuardDuty finding to determine which API calls initiated the finding. Use AWS CloudTrail Insights and AWS CloudTrail Lake to review the API calls in context.



<img width="1094" alt="image" src="https://github.com/user-attachments/assets/ff58b999-42cd-4206-8e89-059fce813e35">


<img width="1078" alt="image" src="https://github.com/user-attachments/assets/7aff14ae-63b1-4fe8-9c77-74b1667b90e7">


![image](https://github.com/user-attachments/assets/3f50259c-efca-4854-afd2-d69d658804ca)



<img width="1047" alt="image" src="https://github.com/user-attachments/assets/f032cde7-d734-4d99-b8fb-6ee29e65ca07">

<img width="1022" alt="image" src="https://github.com/user-attachments/assets/6593d095-3b25-421c-acb3-497a2de9cc84">



<img width="1102" alt="image" src="https://github.com/user-attachments/assets/ead8a521-a72d-4516-aabf-34ccfe834dbe">
B/D ?
<img width="720" alt="image" src="https://github.com/user-attachments/assets/60c7d219-0486-422f-8015-886d3a6906ea">



<img width="1031" alt="image" src="https://github.com/user-attachments/assets/798f747d-d51e-444d-a2a9-61ab7ea49241">

<img width="1017" alt="image" src="https://github.com/user-attachments/assets/c9b61a97-fff1-46cb-90cb-b2f72f4f34d2">


<img width="1063" alt="image" src="https://github.com/user-attachments/assets/13b792e2-dcea-43d8-8931-70ee4b852c3d">

<img width="1075" alt="image" src="https://github.com/user-attachments/assets/6173f666-c97a-4907-aa97-22c729622b01">


<img width="1031" alt="image" src="https://github.com/user-attachments/assets/f963dc0f-f8df-48a3-8621-5b6b5b9ab80c">

<img width="1050" alt="image" src="https://github.com/user-attachments/assets/e8e7a039-8bb9-40d6-b66e-b98105b0ee54">


<img width="1037" alt="image" src="https://github.com/user-attachments/assets/0c92b3f6-69ca-441f-915b-951b0b50c8ef">


<img width="1045" alt="image" src="https://github.com/user-attachments/assets/774af8a8-8f79-4497-803a-a9c8e262c762">
<img width="849" alt="image" src="https://github.com/user-attachments/assets/319890f6-8777-478e-9747-827d2121abef">


<img width="1030" alt="image" src="https://github.com/user-attachments/assets/847a5801-5b64-49e3-978e-694ae79c79b3">
<img width="1038" alt="image" src="https://github.com/user-attachments/assets/4fefaf39-22f1-490e-9243-bebdbf608034">
<img width="752" alt="image" src="https://github.com/user-attachments/assets/726ad737-65f4-42e7-8949-02fcea491240">





<img width="1058" alt="image" src="https://github.com/user-attachments/assets/bee71ba2-02e7-4cf0-b42c-ea196205145c">
<img width="1053" alt="image" src="https://github.com/user-attachments/assets/518be086-9b48-408c-9684-59020b3384fc">
<img width="1041" alt="image" src="https://github.com/user-attachments/assets/833d0b00-838f-47f8-8cff-34f613732f34">

<img width="1001" alt="image" src="https://github.com/user-attachments/assets/a9873602-0d89-41b0-9fbc-76a239c35d13">
<img width="1061" alt="image" src="https://github.com/user-attachments/assets/eabf9772-02e0-4902-8422-2caf5c92234d">
<img width="1014" alt="image" src="https://github.com/user-attachments/assets/de7ae2e6-06fa-484c-8a96-3e9cb3dfffe9">
<img width="1037" alt="image" src="https://github.com/user-attachments/assets/ee9851b4-577a-4126-b912-089ced1b4a97">
<img width="1058" alt="image" src="https://github.com/user-attachments/assets/ef47e8a2-422e-43bc-b453-509d9eb0bb30">

<img width="1020" alt="image" src="https://github.com/user-attachments/assets/ce50c29f-7760-4578-88a5-3ea65910a72c">
<img width="1043" alt="image" src="https://github.com/user-attachments/assets/06905848-5bb9-4f88-bef9-f0f74c5bbe7f">

<img width="1092" alt="image" src="https://github.com/user-attachments/assets/c3b9264d-aa6f-4326-8274-bf2a40a12d87">
<img width="1032" alt="image" src="https://github.com/user-attachments/assets/f95d3bc9-f1c1-419f-b068-9f65cf8e7a9e">
<img width="1031" alt="image" src="https://github.com/user-attachments/assets/0e8178d8-31fa-4531-b224-b1a5b7657757">


<img width="1008" alt="image" src="https://github.com/user-attachments/assets/3385097f-33c2-4ce2-a33c-76a9a44d952f">


<img width="1044" alt="image" src="https://github.com/user-attachments/assets/48672c63-1dfd-44de-99d2-6d30f3a38434">

<img width="1032" alt="image" src="https://github.com/user-attachments/assets/f53b79be-c74e-4fc8-9133-f791954dc52b">

<img width="1046" alt="image" src="https://github.com/user-attachments/assets/7f3c4372-c8fd-4ef1-b49d-b56834466c2b">
<img width="1016" alt="image" src="https://github.com/user-attachments/assets/1b8dd591-509e-412b-a719-35e8f1a82a78">
<img width="716" alt="image" src="https://github.com/user-attachments/assets/ff3d3d3a-2a55-4257-9702-3004a3f2b929">

<img width="1053" alt="image" src="https://github.com/user-attachments/assets/31cc858c-223e-4f6a-88b5-f1804e20c489">
<img width="711" alt="image" src="https://github.com/user-attachments/assets/6053b0e8-19c5-4a74-9b7c-8fb8edc808cb">

<img width="1061" alt="image" src="https://github.com/user-attachments/assets/eb5fa83a-0738-41fa-b644-411d2ab0ef3b">
<img width="1193" alt="image" src="https://github.com/user-attachments/assets/6577b769-2384-4bca-9f96-01808cad83e3">
<img width="1013" alt="image" src="https://github.com/user-attachments/assets/084f505d-f73d-46d5-a843-d3d2bef6872a">

<img width="1096" alt="image" src="https://github.com/user-attachments/assets/c5742303-345b-4525-a5a3-d66e4a21533b">

<img width="1089" alt="image" src="https://github.com/user-attachments/assets/c5396d43-a6d2-4044-96f2-93cfcfcea883">
<img width="741" alt="image" src="https://github.com/user-attachments/assets/4a4e917c-b381-486c-8447-3d11b044051e">
<img width="1059" alt="image" src="https://github.com/user-attachments/assets/6c761fa0-49a4-4ae0-bf68-fc41e27ae9cb">

<img width="1048" alt="image" src="https://github.com/user-attachments/assets/4021af8f-45cf-4c9b-815b-5ff68bbe750d">
<img width="1021" alt="image" src="https://github.com/user-attachments/assets/72c9855a-66d0-4600-9c5a-b9f0a2f990bd">
<img width="1052" alt="image" src="https://github.com/user-attachments/assets/8a466c0d-38a5-4f13-aba8-bf07b3cd0dd3">

<img width="1009" alt="image" src="https://github.com/user-attachments/assets/a995f0b3-b98f-44aa-8e76-4007cbd20dc3">
<img width="814" alt="image" src="https://github.com/user-attachments/assets/3efae6a2-6386-4258-83f8-d72bcd6f8a67">

<img width="1031" alt="image" src="https://github.com/user-attachments/assets/7e01db1a-9d90-4103-ad4e-3a64d6dea206">
<img width="1027" alt="image" src="https://github.com/user-attachments/assets/e001322f-ab08-49c6-8953-db75787d5a8b">



2024/12/01

<img width="1027" alt="image" src="https://github.com/user-attachments/assets/f2a79d19-1a32-472e-8391-6f3b535dc394">
<img width="1003" alt="image" src="https://github.com/user-attachments/assets/217590ea-3df2-4880-b9ce-6d74c01ae9b5">
<img width="1016" alt="image" src="https://github.com/user-attachments/assets/868d1026-0689-4710-8ae2-6d6f7f3e4a94">


<img width="1025" alt="image" src="https://github.com/user-attachments/assets/48423449-a54c-4184-9457-e346bcee3936">
<img width="1057" alt="image" src="https://github.com/user-attachments/assets/2591aefb-d117-4e11-896a-708e8bd5a7ca">


<img width="1076" alt="image" src="https://github.com/user-attachments/assets/65987f53-a492-4e89-8065-0941f0bcbb03">
<img width="1043" alt="image" src="https://github.com/user-attachments/assets/28f48470-16c4-4b6d-9a8e-29b7ee281b3b">
<img width="1057" alt="image" src="https://github.com/user-attachments/assets/2f1d52bd-07d3-42b0-86c1-67958da4b51b">
<img width="1035" alt="image" src="https://github.com/user-attachments/assets/29f5e7dd-69e9-4881-b468-3cf62ae60583">
<img width="1037" alt="image" src="https://github.com/user-attachments/assets/e36e74fc-2938-4efa-be5a-43e3ff9df07d">
<img width="1007" alt="image" src="https://github.com/user-attachments/assets/e0586de9-3d03-4834-8651-dea09a96c576">
<img width="1083" alt="image" src="https://github.com/user-attachments/assets/228ab189-0a7d-4aee-9dda-6c2e1aeb0677">
<img width="1051" alt="image" src="https://github.com/user-attachments/assets/21e10e76-7ea9-4e8b-98a0-82e2d6036bde">
<img width="794" alt="image" src="https://github.com/user-attachments/assets/551e1fb8-6b9b-4213-9730-c8f99d2f197a">
<img width="1031" alt="image" src="https://github.com/user-attachments/assets/aeae47c5-2bea-4a04-982f-c11da432e262">

<img width="1058" alt="image" src="https://github.com/user-attachments/assets/b1e01dee-6b87-49d4-a54a-c9040cfb3ead">
<img width="1020" alt="image" src="https://github.com/user-attachments/assets/56b2a306-7177-4b3b-9186-46d1cae20e5a">
<img width="726" alt="image" src="https://github.com/user-attachments/assets/90657a28-b9a2-43db-b53f-b3f230bdf0ac">


<img width="1012" alt="image" src="https://github.com/user-attachments/assets/4583f22b-b0fb-49ee-a460-584016db2962">

<img width="1056" alt="image" src="https://github.com/user-attachments/assets/95a8a1c9-160e-4ff0-a9f6-b7eb686f83e5">

<img width="1016" alt="image" src="https://github.com/user-attachments/assets/eb342f53-b638-4de6-be12-0a7e0776026d">

<img width="1029" alt="image" src="https://github.com/user-attachments/assets/931d941d-5ed5-480b-bd11-5825ec50a9ce">

<img width="1017" alt="image" src="https://github.com/user-attachments/assets/b32173f0-f8db-47a9-a4ae-e2bb49653082">

<img width="1017" alt="image" src="https://github.com/user-attachments/assets/f13817e8-49ba-41ce-8bf4-ae484fb38229">
Option C Analysis:

Set up a delegated Amazon Security Lake administrator account in Organizations.

Amazon Security Lake is designed to collect, aggregate, and normalize security data from multiple sources into a centralized data lake stored in your account.
By setting up a delegated administrator account, you can manage Security Lake configurations for all member accounts in your AWS Organization.
Enable and configure Security Lake for the organization.

Enable Security Lake at the organizational level to collect logs from all member accounts.
Configure the data sources, such as AWS services, custom applications, and third-party services.
Add the accounts that need monitoring.

Include all relevant AWS accounts in the Security Lake configuration to ensure comprehensive log collection.
This includes accounts running AWS Marketplace offerings that support integration with Security Lake.
Use Amazon Athena to query the log data.

Security Lake stores data in Amazon S3 using the Open Cybersecurity Schema Framework (OCSF) format.
Amazon Athena can be used to run SQL queries against the data stored in S3, allowing for flexible and powerful analysis.
How Option C Meets the Requirements:

Aggregates Logs from the Entire Organization:

Security Lake collects data from all AWS accounts in your organization when enabled.
Centralizes logs from AWS services like VPC Flow Logs, AWS CloudTrail, Amazon Route 53 logs, etc.
Includes AWS Marketplace Offerings:

Security Lake integrates with select AWS Marketplace security solutions that support OCSF.
Allows ingestion of logs from third-party applications running in AWS accounts.
Ingests Logs from On-Premises Systems:

Supports ingestion of data from on-premises systems through custom data sources.
You can format your on-premises logs to comply with OCSF and ingest them into Security Lake.
Normalization of Events:

Automatically normalizes data to the OCSF format, simplifying analysis across different log types.
Reduces the complexity of handling diverse log formats.
Centralized Analysis with Athena:

Amazon Athena provides serverless, ad-hoc querying capabilities.
Enables querying across all aggregated and normalized data without managing any infrastructure.
Scalability and Efficiency:

Security Lake is a fully managed service that scales with your needs.
Reduces operational overhead compared to building and maintaining custom solutions.
Why Other Options Are Less Suitable:

Option A:

Manual Setup and Maintenance:

Requires manual configuration of log deliveries to a centralized S3 bucket in all accounts.
Managing AWS Glue crawlers and ensuring proper schema definitions can be complex.
Limited Integration with On-Premises and AWS Marketplace Logs:

Does not inherently support ingestion and normalization of logs from on-premises systems or AWS Marketplace offerings.
Requires additional custom solutions to ingest and normalize these logs.
Lacks Automatic Normalization:

AWS Glue can help with schema discovery but does not standardize logs into a common format like OCSF.
Option B:

Complexity in Cross-Account Log Streaming:

Setting up CloudWatch Logs streams and subscription filters across multiple accounts is operationally intensive.
Managing permissions and ensuring consistent configurations across accounts is challenging.
Integration Challenges with On-Premises Systems:

Ingesting on-premises logs into CloudWatch Logs requires additional setup and possibly custom scripts or agents.
No Built-in Normalization:

Logs are not automatically normalized, making cross-source analysis more difficult.
Option D:

Incorrect Use of SCPs:

Service Control Policies (SCPs) cannot enforce configuration changes like log delivery settings.
SCPs are used to allow or deny IAM actions across AWS accounts, not to configure services.
Operational Challenges:

Even if possible, pushing configurations via SCPs is not a standard or recommended practice.
Would not address normalization of logs or ingestion from on-premises systems.
No Mention of Normalization or On-Premises Integration:

Does not solve the need to normalize logs.
Does not provide a solution for ingesting on-premises logs.
Conclusion:

Option C is the most suitable solution as it:

Directly addresses all requirements, including aggregation and normalization of logs from AWS accounts, AWS Marketplace offerings, and on-premises systems.
Leverages a managed AWS service (Amazon Security Lake) that simplifies the ingestion, normalization, and storage of log data.
Provides a centralized platform for analysis using Amazon Athena without the need to manage underlying infrastructure.
Ensures scalability and operational efficiency, reducing the need for custom development and maintenance.



<img width="1022" alt="image" src="https://github.com/user-attachments/assets/294fb438-5fbf-4488-86db-1ed08dbee9b8">
Context:

The company needs to implement encryption at rest and enforce least privilege data access controls for sensitive data stored in Amazon S3 and Amazon DynamoDB.
The data is accessed by AWS Lambda functions and container-based services on Amazon EKS running on AWS Fargate.
They have created an AWS KMS customer managed key.
Requirements:

Encrypt all data at rest.
Enforce least privilege data access controls.
Solution Overview:

Option C proposes:

Creating a Key Policy that Allows kms:Decrypt Action Only for Specific Services:

Services Included:
Amazon S3
Amazon DynamoDB
AWS Lambda
Amazon EKS
Creating a Service Control Policy (SCP) that Denies the Creation of Unencrypted Resources:

Denies creation of S3 buckets and DynamoDB tables that are not encrypted with the customer managed KMS key.
Detailed Explanation:

1. Key Policy Restricting kms:Decrypt Action:

Purpose:

Enforces least privilege by ensuring only authorized services can decrypt data using the KMS key.
Prevents unauthorized access to the encrypted data.
Implementation:

Modify the KMS key policy to allow the kms:Decrypt action only for the AWS services that need to access the data.
The key policy would specify the service principals for S3, DynamoDB, Lambda, and EKS.
Example Key Policy Snippet:

{
  "Version": "2012-10-17",
  "Id": "key-policy",
  "Statement": [
    {
      "Sid": "Allow use of the key",
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "s3.amazonaws.com",
          "dynamodb.amazonaws.com",
          "lambda.amazonaws.com",
          "eks.amazonaws.com"
        ]
      },
      "Action": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*"
      ],
      "Resource": "*"
    }
  ]
}
Benefit:

Limits the decryption capability to only the services that require it.
Supports least privilege by not granting unnecessary permissions to other services or principals.
2. SCP Denying Creation of Unencrypted Resources:

Purpose:

Ensures all data at rest is encrypted by preventing the creation of unencrypted S3 buckets and DynamoDB tables.
Enforces compliance with the requirement to encrypt all data at rest.
Implementation:

Apply an SCP at the organizational level that denies the creation of S3 buckets and DynamoDB tables unless they are configured to use the specified KMS key.
Example SCP for S3 Buckets:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedS3Buckets",
      "Effect": "Deny",
      "Action": "s3:CreateBucket",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID"
        }
      }
    }
  ]
}
Example SCP for DynamoDB Tables:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedDynamoDBTables",
      "Effect": "Deny",
      "Action": "dynamodb:CreateTable",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "dynamodb:KmsMasterKeyId": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID"
        }
      }
    }
  ]
}
Benefit:

Prevents users from accidentally or intentionally creating unencrypted resources.
Enforces organizational policies across all AWS accounts in the organization.
Why Option C is Correct:

Meets Both Requirements:

Encryption at Rest: The SCP ensures all new S3 buckets and DynamoDB tables are encrypted using the specified KMS key.
Least Privilege Access Controls: The key policy restricts kms:Decrypt permissions to only the necessary AWS services.
Effective and Enforceable:

SCPs: Apply at the organizational level, ensuring compliance across all accounts.
Key Policies: Control access to the KMS key at a granular level.
Operational Efficiency:

Automated Enforcement: Reduces the need for manual checks or alerts.
Scalable Solution: Works across multiple accounts managed by AWS Organizations.





<img width="853" alt="image" src="https://github.com/user-attachments/assets/a64db2fe-52ef-4c6c-8610-a8e7201cd0fa">

<img width="1004" alt="image" src="https://github.com/user-attachments/assets/a907065c-3852-4f6e-8ba4-bbd0dfc7d0a7">

<img width="1102" alt="image" src="https://github.com/user-attachments/assets/522f1b17-832a-4c48-86b8-b09ae0d9b6a8">

<img width="1106" alt="image" src="https://github.com/user-attachments/assets/097b2784-b4dd-4e7e-81e0-49b8151e13ba">
<img width="701" alt="image" src="https://github.com/user-attachments/assets/7b5f00f6-fbbe-42ce-8cbd-f9d35b617ed7">


<img width="1060" alt="image" src="https://github.com/user-attachments/assets/f2407de3-9517-4fd2-9f1c-db5e062d22fc">
<img width="796" alt="image" src="https://github.com/user-attachments/assets/0a263c0c-4f75-40db-85ee-1c65ad3a2c3e">

<img width="1020" alt="image" src="https://github.com/user-attachments/assets/ad3c1466-d9f0-4340-beeb-3eb763605dd6">
<img width="1167" alt="image" src="https://github.com/user-attachments/assets/0a4e44b4-8b4d-460c-ae19-23657fc39e87">

<img width="1344" alt="image" src="https://github.com/user-attachments/assets/f9e11d1c-86d9-4aed-a35a-cfcf1ee8965f">
<img width="655" alt="image" src="https://github.com/user-attachments/assets/8b331462-7797-4998-b2bf-63e01c519ebc">


<img width="1123" alt="image" src="https://github.com/user-attachments/assets/978fba97-c609-4ebc-a09e-40d53a2fcb5f">
The correct answer is A because GuardDuty can detect and alert on EC2 instance credential exfiltration events.These events indicate that the credentials obtained from the EC2 instance metadata service are being used from an IP address that is owned by a different AWS account than the one that owns the instance1.GuardDuty can also provide details such as the source and destination IP addresses, the AWS account ID of the attacker, and the API calls made using the exfiltrated credentials2.





2024/12/02
<img width="1042" alt="image" src="https://github.com/user-attachments/assets/419a0742-630f-4849-a051-454e512e8c0e">
<img width="775" alt="image" src="https://github.com/user-attachments/assets/89b39545-937d-4322-8467-ed48a6978195">

<img width="1033" alt="image" src="https://github.com/user-attachments/assets/c367bc05-aa86-44d8-a15d-b75c6a40dffd">
<img width="1027" alt="image" src="https://github.com/user-attachments/assets/edd87029-56a1-4644-a992-dc00627e5238">

<img width="1031" alt="image" src="https://github.com/user-attachments/assets/b73ec5d4-d3a6-4cf6-b0ec-c62bff723477">
<img width="598" alt="image" src="https://github.com/user-attachments/assets/0f7d6fa6-80c0-4ce5-b74a-c6e90ac024c9">

<img width="1055" alt="image" src="https://github.com/user-attachments/assets/cd82aae2-1716-42c0-aeb2-6971b3e5a585">

<img width="1099" alt="image" src="https://github.com/user-attachments/assets/4035e00a-b3ee-492f-ba5a-5eb43719e4ee">
<img width="726" alt="image" src="https://github.com/user-attachments/assets/138351bb-2e81-43aa-b4bb-39ac065448e4">

<img width="1042" alt="image" src="https://github.com/user-attachments/assets/b7ccd980-349b-404e-8176-28ce6cd986df">
<img width="744" alt="image" src="https://github.com/user-attachments/assets/7b7398c5-0a43-4235-8196-98bf5b91c723">
<img width="704" alt="image" src="https://github.com/user-attachments/assets/931575ec-55d2-47c8-8c01-5ff6b3da0d03">



2024/12/03

<img width="1034" alt="image" src="https://github.com/user-attachments/assets/8eaae883-0567-404b-b79b-73eabbb5791d">
<img width="793" alt="image" src="https://github.com/user-attachments/assets/52fb9ec2-c19b-4363-8a04-017f0de26020">
<img width="766" alt="image" src="https://github.com/user-attachments/assets/b9fbb9a6-27a4-4ed9-8e69-267fbffd4a99">


<img width="1129" alt="image" src="https://github.com/user-attachments/assets/05bd88aa-825d-465e-851b-e4964ad44bd9">
<img width="773" alt="image" src="https://github.com/user-attachments/assets/5c41a2d2-e6f9-4c6e-8573-5bbc0d68df5f">
<img width="723" alt="image" src="https://github.com/user-attachments/assets/9647f46e-d27c-436f-8b29-0f8451da8df5">

2024/12/04
<img width="1078" alt="image" src="https://github.com/user-attachments/assets/b3c2ba33-90a8-4e1f-9f6e-9150e31ac0b9">
<img width="1054" alt="image" src="https://github.com/user-attachments/assets/161dd718-72a9-4a1c-bf81-421e52b0cd66">
<img width="1050" alt="image" src="https://github.com/user-attachments/assets/f61f898b-a690-4634-bef5-09ed274e8b25">

<img width="1051" alt="image" src="https://github.com/user-attachments/assets/cb584b7f-5171-4bfb-bb1d-3707e04f2109">
<img width="1020" alt="image" src="https://github.com/user-attachments/assets/eb20f00c-a245-4e90-8c02-f3c996b0a7b7">
<img width="805" alt="image" src="https://github.com/user-attachments/assets/92079a48-c5dd-4206-9408-a424e67c555b">

<img width="1021" alt="image" src="https://github.com/user-attachments/assets/296abe4f-ecde-4316-bebd-45c24a9c5da7">
<img width="1037" alt="image" src="https://github.com/user-attachments/assets/2a5a7061-9d57-4bfc-a0e8-02a2d9efbd26">

<img width="979" alt="image" src="https://github.com/user-attachments/assets/df39d178-c0c4-433b-b300-bda42c96b178">


<img width="890" alt="image" src="https://github.com/user-attachments/assets/bf60eb03-64b9-464d-9b32-b645ad5b0c7f">

<img width="865" alt="image" src="https://github.com/user-attachments/assets/b98e5019-0088-4a94-b7ed-eecc999340d8">


<img width="875" alt="image" src="https://github.com/user-attachments/assets/d2573163-6b79-494d-9671-488829b2023c">


2024/12/05
<img width="894" alt="image" src="https://github.com/user-attachments/assets/89866c44-9245-4dd8-8d00-acc14d3272d4">
<img width="689" alt="image" src="https://github.com/user-attachments/assets/af52c3bd-a935-40a5-ad19-38669ece0df8">

<img width="920" alt="image" src="https://github.com/user-attachments/assets/aa426da1-6460-413e-86d6-4665743fb99e">
<img width="628" alt="image" src="https://github.com/user-attachments/assets/877c498e-1ad9-4efe-86e5-ec34608d9f7c">

<img width="840" alt="image" src="https://github.com/user-attachments/assets/09345bff-ef16-428d-ab5c-4e46b2b284af">

<img width="924" alt="image" src="https://github.com/user-attachments/assets/9a48cd80-aa26-455a-9472-1fd7cd98a256">
<img width="773" alt="image" src="https://github.com/user-attachments/assets/4602474c-6bdc-4e82-aae5-8f43a54cc13a">





<img width="910" alt="image" src="https://github.com/user-attachments/assets/b8e7ea99-b0ce-4c3b-a75d-3b5e9af84bcb">



<img width="960" alt="image" src="https://github.com/user-attachments/assets/38c9b69d-ca65-4aa0-aeeb-54e6f7d31e90">

Explanation:

Context and Requirements:

The company uses AWS Organizations and currently has two AWS accounts.
They expect to add more than 50 AWS accounts in the next 12 months.
All existing AWS accounts have Amazon GuardDuty active.
They currently review GuardDuty findings by logging into each AWS account individually.
Requirements:

Centralized View of GuardDuty Findings:

The company wants a centralized view of GuardDuty findings for existing and future AWS accounts.
Automatic GuardDuty Enablement:

Ensure any new AWS account has GuardDuty automatically turned on.
Solution Overview:

To meet these requirements, the company should:

Designate a delegated administrator account for GuardDuty within the organization.
Enable GuardDuty in this delegated administrator account.
Configure GuardDuty to aggregate findings from all member accounts.
Set up automatic enrollment of new AWS accounts into GuardDuty.
Option B Details:

Create a New AWS Account in the Organization:

It's a best practice to have a dedicated security account for centralized security services.
This account acts as the delegated administrator for GuardDuty.
Enable GuardDuty in the New Account:

Activate GuardDuty in the new security account.
This account will collect and aggregate findings from member accounts.
Designate the New Account as the Delegated Administrator for GuardDuty:

Use AWS Organizations to delegate administration of GuardDuty to the new account.
This allows centralized management and monitoring of GuardDuty across the organization.
Configure GuardDuty to Add Existing Accounts as Member Accounts:

Invite or add existing AWS accounts as member accounts in GuardDuty.
The delegated administrator account can view and manage findings from these member accounts.
Select the Option to Automatically Add New AWS Accounts to the Organization:

Enable auto-enable in GuardDuty to automatically include new AWS accounts as member accounts.
This ensures that any new accounts added to the organization will have GuardDuty enabled by default.
Why Option B is Correct:

Meets Requirement 1 (Centralized View):

Aggregates GuardDuty findings from all existing and future AWS accounts into the delegated administrator account.
Provides a single pane of glass for security monitoring.
Meets Requirement 2 (Automatic Enablement):

The auto-enable feature in GuardDuty ensures that new accounts automatically have GuardDuty enabled and are added as member accounts.
Follows Best Practices:

Using a dedicated security account aligns with AWS security best practices for centralized security management.



<img width="909" alt="image" src="https://github.com/user-attachments/assets/a16f79c7-620f-460c-aabf-c75609b18e09">





<img width="633" alt="image" src="https://github.com/user-attachments/assets/af4dbe2d-66f6-40c5-88e0-4611179afa11">
<img width="635" alt="image" src="https://github.com/user-attachments/assets/2459b11c-e200-455c-ba4e-6e61d4163a30">
<img width="1101" alt="image" src="https://github.com/user-attachments/assets/99a0a719-ecdc-42ea-8720-f4b4054650bc">
<img width="579" alt="image" src="https://github.com/user-attachments/assets/e47d6024-6590-4a55-914a-18212afbd776">
<img width="1119" alt="image" src="https://github.com/user-attachments/assets/bf4d8d1a-2563-4b38-97ff-b2d7e9fad0fe">
<img width="667" alt="image" src="https://github.com/user-attachments/assets/1ece9934-cdbd-4163-a6f0-02de91ca7701">
<img width="1119" alt="image" src="https://github.com/user-attachments/assets/e2fa6164-34a8-4caa-a16d-aad8787a2b8b">
<img width="1119" alt="image" src="https://github.com/user-attachments/assets/b420809e-3d30-478f-a494-41116e1442ed">
<img width="1106" alt="image" src="https://github.com/user-attachments/assets/5166e90e-3bc6-401a-882c-d76f7b469bb2">
<img width="1101" alt="image" src="https://github.com/user-attachments/assets/f011b442-6efc-4225-8ba7-e46ee1e777fa">
<img width="1116" alt="image" src="https://github.com/user-attachments/assets/2ea5b215-4096-465a-a478-872fe7a0eb76">
<img width="1094" alt="image" src="https://github.com/user-attachments/assets/12751c0b-136e-4145-b560-6303f70d3cdb">
<img width="652" alt="image" src="https://github.com/user-attachments/assets/951be51b-cbcf-4edc-9385-6ce27f2e33b3">
<img width="1111" alt="image" src="https://github.com/user-attachments/assets/9f7aa142-7dce-4b37-9662-b39423a335fd">
<img width="561" alt="image" src="https://github.com/user-attachments/assets/7fcd73b6-8af6-4813-b2e4-a4657efa5787">

<img width="1107" alt="image" src="https://github.com/user-attachments/assets/3be9e8e5-937a-4723-a3c4-6d2a9caaf4b3">
<img width="693" alt="image" src="https://github.com/user-attachments/assets/adc60e58-ceba-4665-aebf-3be8f6e7a947">
<img width="637" alt="image" src="https://github.com/user-attachments/assets/59e64282-3458-4ea0-baa2-81b8d60a4262">
<img width="1188" alt="image" src="https://github.com/user-attachments/assets/71cfef92-271f-4cc5-a89a-cd8d74e1a927">
<img width="774" alt="image" src="https://github.com/user-attachments/assets/09c42f71-b0fb-4692-9a9c-d920f23bff68">
<img width="774" alt="image" src="https://github.com/user-attachments/assets/09c42f71-b0fb-4692-9a9c-d920f23bff68">
<img width="636" alt="image" src="https://github.com/user-attachments/assets/0051e902-7e09-4c73-8920-54d7246decda">
<img width="1110" alt="image" src="https://github.com/user-attachments/assets/4540391c-389f-4df0-b027-43f960372707">
<img width="1129" alt="image" src="https://github.com/user-attachments/assets/39152892-99d8-4fdb-b5b9-da8782241fc6">
<img width="1115" alt="image" src="https://github.com/user-attachments/assets/0c0ba79d-a3b1-40f1-a60b-a44b7f356e82">
<img width="621" alt="image" src="https://github.com/user-attachments/assets/43f010e2-0337-4d39-8afe-076e24f47742">
<img width="1113" alt="image" src="https://github.com/user-attachments/assets/240276f4-bbef-42e4-8c1d-bdd431911e1c">
<img width="1112" alt="image" src="https://github.com/user-attachments/assets/6edb4fab-178f-4611-9a28-26d086827f13">
<img width="1140" alt="image" src="https://github.com/user-attachments/assets/d03cd415-95b6-459b-aab9-1744263567a2">
<img width="1154" alt="image" src="https://github.com/user-attachments/assets/3085b26e-fb90-4eeb-91b7-adf00fb77707">
<img width="1148" alt="image" src="https://github.com/user-attachments/assets/81de33aa-15fc-46aa-9c2b-c38826eeea4d">
<img width="1111" alt="image" src="https://github.com/user-attachments/assets/8c1817fd-ce56-4ce3-ad05-ebd21fb37312">
<img width="1157" alt="image" src="https://github.com/user-attachments/assets/c8851ae5-ecb8-4be4-b339-d3d1ad22504b">
<img width="1113" alt="image" src="https://github.com/user-attachments/assets/c6578ae8-84bc-47e9-b25d-3273e508bf93">
<img width="1130" alt="image" src="https://github.com/user-attachments/assets/f3188c4a-8378-4176-8103-3de2e739b11b">
<img width="610" alt="image" src="https://github.com/user-attachments/assets/92c0a6da-9afb-4565-bc1f-36c87e5f9163">
<img width="1107" alt="image" src="https://github.com/user-attachments/assets/ec72e50b-8791-4355-92e9-1f6b2b1f5d96">
<img width="680" alt="image" src="https://github.com/user-attachments/assets/6ac7dcd0-0bc2-40a3-af65-6411d9301376">
<img width="1118" alt="image" src="https://github.com/user-attachments/assets/eed1a883-e319-456b-92c9-cdcd2342151f">
<img width="1113" alt="image" src="https://github.com/user-attachments/assets/2921285c-5869-4efd-bbd3-e4158224fb6b">
<img width="704" alt="image" src="https://github.com/user-attachments/assets/c1ba6d5f-c586-49dd-882f-31a15ac2c704">
<img width="1116" alt="image" src="https://github.com/user-attachments/assets/081b1c24-10f6-4577-b84b-c4417d4dbe04">
<img width="657" alt="image" src="https://github.com/user-attachments/assets/3385d6ba-aa07-4190-ad4c-df9dae9acfd7">
<img width="1113" alt="image" src="https://github.com/user-attachments/assets/a222a30f-cd21-4395-bba4-4f9ba9c5d82c">
<img width="1092" alt="image" src="https://github.com/user-attachments/assets/96eb1da6-570f-47eb-8b3b-3882a2b8625a">
<img width="652" alt="image" src="https://github.com/user-attachments/assets/a30fb820-d53a-4bba-820c-f6ba70596e0a">
<img width="1116" alt="image" src="https://github.com/user-attachments/assets/06ab1a91-bf4e-40f5-9413-5f4b102b9f9f">
<img width="662" alt="image" src="https://github.com/user-attachments/assets/59ef8620-1334-4bf3-a905-4ff3dd691a38">
<img width="1098" alt="image" src="https://github.com/user-attachments/assets/eae0f22a-ae35-400e-8e6c-6bf5571521dc">
<img width="628" alt="image" src="https://github.com/user-attachments/assets/5f25e337-5021-4eb8-aaf8-b1331f90b125">
<img width="1107" alt="image" src="https://github.com/user-attachments/assets/c09dd595-9cd4-4c74-b104-9f9888991bb4">
<img width="738" alt="image" src="https://github.com/user-attachments/assets/f508f62b-0e90-4e4d-a0d9-27aeb35e1ef6">
<img width="1109" alt="image" src="https://github.com/user-attachments/assets/e0cdce9e-4338-48fa-93af-435028028257">
<img width="673" alt="image" src="https://github.com/user-attachments/assets/c223b830-474b-4e3f-af15-013ec19eef70">

<img width="1127" alt="image" src="https://github.com/user-attachments/assets/98081beb-2ca0-48f9-8a73-1e726e904133">
<img width="748" alt="image" src="https://github.com/user-attachments/assets/b696b4ca-6851-4a81-ad29-087d988b1150">
<img width="1127" alt="image" src="https://github.com/user-attachments/assets/8787a810-a1a9-4c0c-8263-bbcfcce9604d">
<img width="1114" alt="image" src="https://github.com/user-attachments/assets/145c6899-c01d-4a93-949c-7fd693dfd1ba">
<img width="1110" alt="image" src="https://github.com/user-attachments/assets/9903c130-2bc5-4f6e-9de5-bd8079162a2e">
<img width="1115" alt="image" src="https://github.com/user-attachments/assets/e1a4329c-8f79-4325-ba56-8d6807c8d638">
<img width="784" alt="image" src="https://github.com/user-attachments/assets/f4625fd1-7704-4b8d-83ba-3fab9bf2fae5">
<img width="1113" alt="image" src="https://github.com/user-attachments/assets/0786a19b-9796-41d5-97f4-4d562798ebdc">
<img width="711" alt="image" src="https://github.com/user-attachments/assets/39544143-ce17-4696-be7a-d28f8a6f8b83">
<img width="1112" alt="image" src="https://github.com/user-attachments/assets/16b83b19-2d77-4f2f-adc6-dbaddbcf6955">
<img width="771" alt="image" src="https://github.com/user-attachments/assets/a7e1b51a-fd92-4fda-bb28-4d3ee7d2ec44">
<img width="1105" alt="image" src="https://github.com/user-attachments/assets/db29cbc4-19c1-4104-80d8-5df03914c13f">
<img width="1111" alt="image" src="https://github.com/user-attachments/assets/be60b428-376f-4f85-ba68-1f65846f1e36">

<img width="623" alt="image" src="https://github.com/user-attachments/assets/77211b5d-265e-433e-a62d-d6d0d8ababbd">

<img width="1151" alt="image" src="https://github.com/user-attachments/assets/e2b81623-3a07-40f3-a85b-d30b14c7442d">




<img width="894" alt="image" src="https://github.com/user-attachments/assets/d0c682d5-8d10-41a0-a8f7-e450d543aa5a">
<img width="920" alt="image" src="https://github.com/user-attachments/assets/3458b26d-9b02-451c-a8e1-72e5b5747cf8">
<img width="912" alt="image" src="https://github.com/user-attachments/assets/d6b84c2e-378b-4b45-be62-9855d351cdbf">
<img width="904" alt="image" src="https://github.com/user-attachments/assets/a4aa7a13-bb51-44b1-80a4-c3605f77092e">
<img width="952" alt="image" src="https://github.com/user-attachments/assets/24fd9e25-8be7-4e24-8387-b08bc45d06e1">
<img width="856" alt="image" src="https://github.com/user-attachments/assets/7cf22cec-3fdc-4124-b627-706ddda62970">
<img width="868" alt="image" src="https://github.com/user-attachments/assets/c210b8ee-a68c-4d8e-a8ea-4d5fda10e4ea">
<img width="867" alt="image" src="https://github.com/user-attachments/assets/97d2eb7c-b5d7-4cbf-af91-0c36cf3ebf45">
<img width="941" alt="image" src="https://github.com/user-attachments/assets/c77f0fb0-38f9-472b-b3eb-db2e1a410132">
<img width="930" alt="image" src="https://github.com/user-attachments/assets/4b59d742-530c-4296-819f-46af47855acd">
<img width="947" alt="image" src="https://github.com/user-attachments/assets/f1e5115b-a9c9-4195-9a1e-6cfc65dc42d4">
<img width="940" alt="image" src="https://github.com/user-attachments/assets/f295b2db-0287-4a4a-899c-9e6f820d2627">
<img width="928" alt="image" src="https://github.com/user-attachments/assets/8c1fc221-b6de-4422-b67d-5f82ebffa0bb">
<img width="881" alt="image" src="https://github.com/user-attachments/assets/4e49449e-7be3-42b1-8c35-2ee1c44fd345">
<img width="934" alt="image" src="https://github.com/user-attachments/assets/8ac73596-4bd1-44aa-855e-0283cd53b09c">
<img width="972" alt="image" src="https://github.com/user-attachments/assets/75ebc199-182d-4bd4-af29-dd09e64e9d95">
<img width="899" alt="image" src="https://github.com/user-attachments/assets/86737075-40bf-41fd-9555-cf6609f3a544">
<img width="940" alt="image" src="https://github.com/user-attachments/assets/252bc0e2-a64f-4eef-8f39-60667fff0ed0">


<img width="861" alt="image" src="https://github.com/user-attachments/assets/e77d0c7d-5e7c-437f-8b43-04f11f0bb833">
<img width="975" alt="image" src="https://github.com/user-attachments/assets/2f43e750-7e27-4bef-b64f-907e98102de4">
<img width="919" alt="image" src="https://github.com/user-attachments/assets/8a39571f-7213-494e-a19d-a607748dc795">
<img width="854" alt="image" src="https://github.com/user-attachments/assets/069c01b7-64c7-44c9-a4c3-2ae108f0cdff">
<img width="732" alt="image" src="https://github.com/user-attachments/assets/f974aaa6-ae70-4335-a5cd-bda81c9bd3cc">
<img width="881" alt="image" src="https://github.com/user-attachments/assets/e92d4620-f8ec-47e5-86ec-d1a350fc3ba1">
<img width="888" alt="image" src="https://github.com/user-attachments/assets/618b6e84-9c2e-406c-97f7-896ac569abde">
<img width="973" alt="image" src="https://github.com/user-attachments/assets/a37675ea-ebb1-436b-89a8-1992753e49df">
<img width="952" alt="image" src="https://github.com/user-attachments/assets/7e77a0be-d427-4906-8a16-0d87e6ee4d69">
<img width="851" alt="image" src="https://github.com/user-attachments/assets/2c6a4c66-20c7-48ed-ade1-83988fe25d22">
<img width="830" alt="image" src="https://github.com/user-attachments/assets/ea8e7069-77e2-47d6-8f7a-c65d1bd9bbd2">
<img width="972" alt="image" src="https://github.com/user-attachments/assets/01f52c7c-db72-456e-9ad0-f234bdf912b5">
<img width="864" alt="image" src="https://github.com/user-attachments/assets/ecd6729f-4b65-4329-9019-2b25e6bc7d80">
<img width="898" alt="image" src="https://github.com/user-attachments/assets/1319aa31-78d5-4333-b410-5024e51324fe">
<img width="723" alt="image" src="https://github.com/user-attachments/assets/74ea3a80-260a-4d9a-b3af-4658156b9441">
<img width="803" alt="image" src="https://github.com/user-attachments/assets/43988f75-a494-4883-aacd-8604aa5e363d">




<img width="923" alt="image" src="https://github.com/user-attachments/assets/d11d5a1f-ec23-4299-b329-1fe5ae1a4474">
<img width="860" alt="image" src="https://github.com/user-attachments/assets/c5bbed9a-e27a-4a75-919f-96161881960a">
<img width="879" alt="image" src="https://github.com/user-attachments/assets/e0fd0d36-c99a-4796-8f8b-3fa5c4e9c1b8">
<img width="903" alt="image" src="https://github.com/user-attachments/assets/24396385-816c-4a49-af89-bbd2eb4360dc">
<img width="731" alt="image" src="https://github.com/user-attachments/assets/320e1cbc-642b-481b-91a2-bb7c6295fe1c">



<img width="933" alt="image" src="https://github.com/user-attachments/assets/6fe74b05-7fbf-4a3e-814a-55007a957b04">
<img width="890" alt="image" src="https://github.com/user-attachments/assets/cec069e9-eda4-4e9c-9e41-4bdbb0ec3ab6">
<img width="893" alt="image" src="https://github.com/user-attachments/assets/8301d2fa-a870-4f19-9f6d-e7b09a7b0023">
<img width="882" alt="image" src="https://github.com/user-attachments/assets/dabed771-6d78-496c-99c2-fbaf97440a79">
<img width="1006" alt="image" src="https://github.com/user-attachments/assets/9b80eab3-7b05-4eaf-9978-c2b22ee36948">
<img width="716" alt="image" src="https://github.com/user-attachments/assets/35cfc79e-65c0-4f1e-bda5-91c00ad81609">
<img width="639" alt="image" src="https://github.com/user-attachments/assets/41b42d7b-17aa-4339-9693-3094f1098e0b">
<img width="898" alt="image" src="https://github.com/user-attachments/assets/e10f0c6a-d1d1-4612-b52c-f9dd86578b56">
<img width="925" alt="image" src="https://github.com/user-attachments/assets/7951a510-5a59-42cd-88b0-7bb88ee4157b">
<img width="925" alt="image" src="https://github.com/user-attachments/assets/ce1ee32e-9bc6-44bd-96fc-29c18fe5b804">
<img width="896" alt="image" src="https://github.com/user-attachments/assets/3d4eb079-2094-43d6-84c1-15c8cd7699f0">


<img width="863" alt="image" src="https://github.com/user-attachments/assets/9ebbc0d8-70bf-4acc-97a9-c5ed6de21bb6">
<img width="885" alt="image" src="https://github.com/user-attachments/assets/40c1425b-5362-4bab-934c-28dbf7e53e95">
<img width="835" alt="image" src="https://github.com/user-attachments/assets/0fc4149c-2fc2-4634-bb85-f73e83555b4f">
<img width="869" alt="image" src="https://github.com/user-attachments/assets/f98c4c4c-36cc-4cf2-aacb-0f679c84f0cb">

<img width="916" alt="image" src="https://github.com/user-attachments/assets/7c23ceab-5eea-4666-a6d0-ecd7b65c5b04">

<img width="747" alt="image" src="https://github.com/user-attachments/assets/a08975ca-7538-4a9d-a6f1-b537a0041dca">

<img width="913" alt="image" src="https://github.com/user-attachments/assets/14b3087e-5849-4d41-bf9e-0ec131cab4da">
<img width="577" alt="image" src="https://github.com/user-attachments/assets/e79b3f75-5070-40cf-b81a-02ce7f6e5dc1">
<img width="913" alt="image" src="https://github.com/user-attachments/assets/e5562be9-cfe8-4b07-82ab-fbd62722cfdc">
<img width="648" alt="image" src="https://github.com/user-attachments/assets/3fed5b38-49ef-4548-b19b-cf57a2f1012e">
<img width="866" alt="image" src="https://github.com/user-attachments/assets/12fe1a2f-06aa-43b7-9fc4-17fd7b96adbf">




<img width="556" alt="image" src="https://github.com/user-attachments/assets/6d7ff5c0-c34d-4b13-bc39-bd15feab92d6">
<img width="664" alt="image" src="https://github.com/user-attachments/assets/805ff606-3882-4eba-8b17-1bb73df91e3d">
<img width="1595" alt="image" src="https://github.com/user-attachments/assets/a1768224-7642-4270-96a7-e2d3d1d9ca3c">
<img width="1593" alt="image" src="https://github.com/user-attachments/assets/70910111-c7f3-4656-9175-4019367b6722">
<img width="1625" alt="image" src="https://github.com/user-attachments/assets/03334132-df55-4d6f-9a2b-8a614d8c9487">
<img width="1658" alt="image" src="https://github.com/user-attachments/assets/6e8ce4c6-155a-42d6-9a0a-34854dc997c7">
<img width="1528" alt="image" src="https://github.com/user-attachments/assets/c7b00c3f-8541-4619-8a3c-da5fe751fa03">
<img width="552" alt="image" src="https://github.com/user-attachments/assets/c433187e-a4f7-4ccc-a1f9-4522aa5ed1aa">


<img width="1121" alt="image" src="https://github.com/user-attachments/assets/47cc9d22-281c-4508-93e8-089885cfd5b5">
<img width="1101" alt="image" src="https://github.com/user-attachments/assets/4bff8641-e3b5-403f-81d7-009741cfe09a">
<img width="1109" alt="image" src="https://github.com/user-attachments/assets/a320eb5b-87f1-4620-81e9-65305421e5c4">
<img width="1115" alt="image" src="https://github.com/user-attachments/assets/76627618-3405-4584-ae9d-410eb6f4dbac">


# Cognito user pool and identity pool

![image](https://github.com/user-attachments/assets/2d49fe29-dd13-4a98-bf3c-fb45f066b1a4)
![image](https://github.com/user-attachments/assets/6298c9a0-9eb2-4fd3-b69d-5331a393a526)
![image](https://github.com/user-attachments/assets/ed255cf9-dcfe-4030-bbd4-9d07cab6e04c)
![image](https://github.com/user-attachments/assets/f032a01f-1617-4e6a-980a-1f005714d35a)
![image](https://github.com/user-attachments/assets/55c7f914-794e-4478-b21b-1572fd7a3c8e)

for a mobile application. In this situation, you can leverage Amazon Cognito identity pools to obtain temporary AWS credentials to access the AWS services or resources you need. Cognito identity pools act as an identity federation mechanism to exchange the credentials that you provide, either from AWS or third-party identity providers (including social identity providers such as Google, Apple, Amazon, etc.), in the form of an OIDC token or a SAML assertion with temporary AWS credentials.

# DNS spoofing protection 
<img width="1579" alt="image" src="https://github.com/user-attachments/assets/0979b081-a441-4ae9-b6c1-bf815e9cf6d6">
<img width="1553" alt="image" src="https://github.com/user-attachments/assets/9ceb008d-4b5f-412f-a5d3-2cb1e83b4fa0">
<img width="1613" alt="image" src="https://github.com/user-attachments/assets/008c6156-865b-43d3-962c-3ae9052855c1">

# AWS WAF protect only regional API Gateway, for edge optimized one, create a custom CloudFront distribution in front of your API Gateway
<img width="517" alt="image" src="https://github.com/user-attachments/assets/86895c35-ea64-4e38-bc7d-0391732712f0">
<img width="1531" alt="image" src="https://github.com/user-attachments/assets/f2d3d702-dcfd-4093-9798-cd210640220f">
<img width="609" alt="image" src="https://github.com/user-attachments/assets/9c5fe184-2f6e-4b22-ba94-318500515bff">


# AWS Shield
You can secure the perimeter of your AWS environment using AWS Shield Standard. This service comes free of charge and is activated by default for every AWS account, protecting your AWS resources from infrastructure attacks that are common at layers 3 (network layer, typically for the IP protocol) and 4 (transport layer, e.g. for TCP or UDP protocols) of the OSI model, such as SYN/UDP floods, reflection attacks, and so on. If your workloads deployed on AWS are likely to become particularly exposed to such external attacks, you can opt for more sophisticated protection with AWS Shield Advanced. Shield Advanced offers extra protection on layers 3 and 4 and also at layer 7 (application layer, e.g., HTTP/S protocols) of the OSI model.

Shield Advanced lets you be more specific about the protection of your exposed AWS resources. You can, for instance, protect your publicly accessible web applications or APIs using the integration of Shield Advanced with AWS services such as Amazon CloudFront, AWS WAF, Amazon Application Load Balancer, Amazon Network Load Balancer, Amazon Elastic Cloud Compute (Amazon EC2), and Amazon Route 53. Shield Advanced will also automatically deploy Network Access Control Lists (Network ACLs or NACLs) that you defined to protect resources such as EC2 instances or Elastic IP addresses, at the border of the AWS network to protect these resources against large DDoS Attacks (an order of magnitude bigger than what you could handle at the VPC level). It can also manage WAF Web ACLs on your behalf to take measures automatically against detected DDoS events at layer 7. Shield Advanced also gives you access to the AWS Shield Response Team (SRT), which can either proactively reach out to you in case of a suspected DDoS event or assist you if you’re already affected by such an event. Finally, Shield Advanced provides financial protection against any extra costs incurred due to the scaling of the AWS resources under its protection. In case there is abnormal scaling and exceptional costs on AWS resources that were protected by Shield Advanced, you will be entitled to AWS credits to compensate for the generated extra costs.

# AWS Firewall Manager
If you operate in an AWS environment with multiple AWS accounts and resources that require protection, AWS Firewall Manager can make your life easier by providing a central location where you can set up protection. You can then roll out this protection across multiple accounts and resources in your AWS environment. Firewall Manager integrates with Shield Advanced, WAF, AWS Network Firewall, and Route 53 Resolver DNS Firewall. The idea is to leverage Firewall Manager to apply the same protection baseline to your entire organization or whenever you deploy a new application in your AWS environment, making sure it complies with your security rules. This method is much easier operationally and less error-prone than repeating the configuration again and again from account to account.

# Route 53
Route 53, AWS’s DNS service, also provides extra security measures to protect against attacks on the DNS protocol. First, you can leverage Route 53 Resolver DNS Firewall to filter outbound DNS requests from your own VPCs. Such requests go through Resolver to resolve domain names. If one of your workloads has been compromised by an attacker, they may want to exfiltrate data from your AWS environment by conducting a DNS lookup to a domain they control. DNS Firewall lets you monitor and control the domains that can be queried from your VPCs, so you can, for instance, allow access to only the domains you explicitly trust (allow-listing) or block queries to well-known untrustworthy domains and let all other queries through. DNS Firewall manages the lists of known bad domains, keeping them up to date, to make your life easier.

Second, you can enable DNSSEC validation on Route 53 Resolver in your VPCs. This will instruct Resolver to validate the cryptographic signature of the response you get upon a DNS lookup, thereby ensuring that the response was not tampered with. Note that Route 53 Resolver does not, at this stage, return the DNSSEC response, so if you require a custom validation of that response, you would need to rely on a different mechanism for DNS resolution.


# SAML IdP
![image](https://github.com/user-attachments/assets/a7f96b3e-5da8-4f07-9fb0-2f60bb17980d)

![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/592bcba6-170a-417a-a5f9-ff3b124a9e34)

![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/8b2b1d92-feb4-4aff-9e51-b9155c286f17)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/85164a3b-ac5d-44d6-a2ac-de859828fa6b)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/1cad6d8d-b3b2-4e20-9edf-5979e16756f9)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/f5888b49-45d9-44d4-ac73-b83a856f0782)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/1cd92aef-2107-4466-b662-cbe31c1a430e)

![image](https://github.com/user-attachments/assets/f4b1caba-831b-47a1-93cb-bd5d2f4804a8)
![image](https://github.com/user-attachments/assets/337275c9-c753-47fe-a9d8-38b9569244a5)
![image](https://github.com/user-attachments/assets/8d4ba70b-4abe-47f4-8f03-5b9a89e36425)


# ACM public certificate or private certificate 

![image](https://github.com/user-attachments/assets/fcde4afe-bb2f-4454-bfe1-a0ac19db837a)
While the primary use case of ACM is to provide SSL/TLS certificates for public and private websites, it also offers a valuable feature called AWS Private CA (previously ACM Private CA). 
![image](https://github.com/user-attachments/assets/abb8f603-063a-407a-9224-76f443f78cd3)

![image](https://github.com/user-attachments/assets/ec4facb2-50e3-4710-9e98-e2f926c4c6d4)
![image](https://github.com/user-attachments/assets/241de2a1-60bc-4cde-ae93-6fc4d19e95a1)
A private CA in ACM provides a dedicated and controlled environment for generating and maintaining digital certificates, ensuring the confidentiality and integrity of sensitive data transmissions. This service allows users to issue and manage certificates for internal resources, applications, and devices, providing a robust security layer within the AWS ecosystem. By leveraging private CAs in ACM, not only can users establish trust within their infrastructure, encrypt communications, and enhance overall data protection, but they can also confidently manage their certificate life cycle, streamline security practices, and meet compliance requirements, even for complex and dynamic cloud environments.



# 2 Logging and Monitoring Domain
![image](https://user-images.githubusercontent.com/36766101/227768029-9bdda751-353b-4c7a-a4d2-e2843ce15685.png)
![image](https://user-images.githubusercontent.com/36766101/227768427-31696707-efe4-482e-90fe-2c23ed9448d5.png)
![image](https://user-images.githubusercontent.com/36766101/227768995-c1cb01dc-aee8-428c-bdba-aabd9f83c502.png)

![image](https://user-images.githubusercontent.com/36766101/227768831-a7376d6f-242c-498c-9093-720e12136d3c.png)
![image](https://user-images.githubusercontent.com/36766101/227769284-afd84e60-f2c4-4ebf-8683-da1323ace62e.png)
![image](https://user-images.githubusercontent.com/36766101/227769616-daa23666-210b-4c2a-afc3-70ca7fff02a6.png)
![image](https://user-images.githubusercontent.com/36766101/227769678-5aaa4c69-35df-4eed-9457-279b416238a7.png)
![image](https://user-images.githubusercontent.com/36766101/227769732-ff6de14d-5b8f-4bf8-8a1b-02b6fe0a0f9c.png)
![image](https://user-images.githubusercontent.com/36766101/227769892-68022118-337a-40cb-a39d-ce9770e34d20.png)
![image](https://user-images.githubusercontent.com/36766101/227770802-4990fa5f-bb2e-4bd0-a89a-2f4e1536baa5.png)
![image](https://user-images.githubusercontent.com/36766101/227770932-85155af7-12e6-4cd3-9b2f-42a1fa7a5661.png)
![image](https://user-images.githubusercontent.com/36766101/227770981-33c4a648-f0a9-4ecf-be90-646d4e91b930.png)
AWS configure aggregator 
![image](https://user-images.githubusercontent.com/36766101/227825639-4be679fb-1675-4362-979e-cd8c6fa8305e.png)
![image](https://user-images.githubusercontent.com/36766101/227825875-c45bbaf3-30ff-4e15-9ff2-74a850861b2b.png)

AWS GuardDuty
![image](https://user-images.githubusercontent.com/36766101/227827505-cfe4527e-0ef7-415e-9be8-fce99ed1f44a.png)

AWS EC2 Inspector vulnerability finding
![image](https://user-images.githubusercontent.com/36766101/228137026-58970b36-debc-4680-8262-0ac40b1b0928.png)
![image](https://user-images.githubusercontent.com/36766101/228137592-07b393c3-aa92-4b6f-8f0b-e9c4707b651d.png)
![image](https://user-images.githubusercontent.com/36766101/228203313-a8161495-5dff-4abf-bf75-78b713dfd6f1.png)

AWS EC2 SSM run command to remove comprised public key
![image](https://user-images.githubusercontent.com/36766101/228142280-ffe2b94c-f411-40a9-bf11-232c597d6fb7.png)


AWS Abuse example
![image](https://user-images.githubusercontent.com/36766101/228146375-9fc94161-7f58-4f41-bff8-d1d567ac1c7a.png)
![image](https://user-images.githubusercontent.com/36766101/228146504-52789c9e-4488-4a0b-a8db-338a7d9fc179.png)

AWS KMS delete key
![image](https://user-images.githubusercontent.com/36766101/228386747-395617d1-1a28-417e-8395-66226702bd91.png)
![image](https://user-images.githubusercontent.com/36766101/228386901-bd6744cf-392c-4065-9399-aa3f57760a86.png)

AWS KMS multiple-region key
![image](https://user-images.githubusercontent.com/36766101/228702878-860b4f25-5589-45f5-b004-d12121632dfe.png)
![image](https://user-images.githubusercontent.com/36766101/228702721-5682e7a9-0732-4a12-8aec-c6e51f6bb27d.png)

AWS S3 server side encryption (SSE-C, SSE-S3(AES)，SSE-KMS )
![image](https://user-images.githubusercontent.com/36766101/228707965-c80dc3b1-9970-4035-aaa0-8f52e4e6519b.png)
![image](https://user-images.githubusercontent.com/36766101/228710389-20a077d6-da89-4b74-b5ad-242c2354f71c.png)

![image](https://user-images.githubusercontent.com/36766101/227846695-fc778dc3-2dcd-49ab-9997-0b131480dc7d.png)
![image](https://user-images.githubusercontent.com/36766101/227846783-f0bb06db-439c-4ce2-bc56-967d940ae2c1.png)
![image](https://user-images.githubusercontent.com/36766101/227846881-ed2b2d51-0f15-4515-b697-f8026551ee82.png)
![image](https://user-images.githubusercontent.com/36766101/227846983-566883cf-5f3d-4a05-81e4-d9ba52ded6d8.png)
![image](https://user-images.githubusercontent.com/36766101/227847076-baa565c3-351e-47db-b0d7-6b124c92d552.png)
![image](https://user-images.githubusercontent.com/36766101/227847181-fe5dfd80-5683-4785-a4d0-c7c8e2873072.png)
![image](https://user-images.githubusercontent.com/36766101/227847385-44732103-68f6-43ca-8821-43993a1ce8c6.png)
![image](https://user-images.githubusercontent.com/36766101/227847545-f985190d-52e6-4ed1-9eae-dfdcca8782ca.png)
![image](https://user-images.githubusercontent.com/36766101/227847598-2347cd78-10ea-4ba6-a134-18626131304c.png)
![image](https://user-images.githubusercontent.com/36766101/227847848-7bd33649-55b0-4e40-9079-41f41d7b6db4.png)
![image](https://user-images.githubusercontent.com/36766101/227848004-0263cc27-f1ec-47b0-b71d-c2d844c6399e.png)
![image](https://user-images.githubusercontent.com/36766101/227848120-93945f19-fde4-4381-bed7-9d02d36e3755.png)
![image](https://user-images.githubusercontent.com/36766101/227848339-581e013e-f9d7-47ee-a9eb-930ec4cd272d.png)
![image](https://user-images.githubusercontent.com/36766101/227848505-56bb1750-cf39-4b64-b317-96501d5758a0.png)
![image](https://user-images.githubusercontent.com/36766101/227849037-62d219c4-8e66-449c-83da-5ef192d41752.png)
![image](https://user-images.githubusercontent.com/36766101/227849174-ea9e9fc5-c21c-4c84-9657-d75478278791.png)
![image](https://user-images.githubusercontent.com/36766101/227849303-7efe1bae-0bfc-4704-8350-e8ffd25161c4.png)
![image](https://user-images.githubusercontent.com/36766101/227850163-8a0d2a67-c587-4b53-ba4f-1f295f3a55db.png)
![image](https://user-images.githubusercontent.com/36766101/227850305-1eb5d500-4680-42d5-a7c2-dc7d15c4c3cf.png)
![image](https://user-images.githubusercontent.com/36766101/227850408-54d6c2d1-cbf0-436e-bdaf-607687d369cf.png)
![image](https://user-images.githubusercontent.com/36766101/227850498-fc9523f2-f28d-4d55-92e6-e145d40348fa.png)
![image](https://user-images.githubusercontent.com/36766101/227850614-85eb0b3f-75ff-4c62-8f39-ff542d8cf2fc.png)
![image](https://user-images.githubusercontent.com/36766101/227851027-3ebbf126-74b7-4092-9700-3a2cee268ab7.png)
![image](https://user-images.githubusercontent.com/36766101/227851090-cb8c12c8-05bd-4d3c-bd6a-279ce3cb3366.png)
![image](https://user-images.githubusercontent.com/36766101/227851240-37524e21-6bb3-44ed-a99c-7a922c27699d.png)
![image](https://user-images.githubusercontent.com/36766101/227852170-5b7a12d5-7730-4be1-a73c-5e4b65802395.png)
![image](https://user-images.githubusercontent.com/36766101/227852285-86ae00f8-8149-4b1b-92b0-d6a039c4f978.png)
![image](https://user-images.githubusercontent.com/36766101/227852390-b3e493ea-a381-449c-a314-707e4cd2fcb0.png)
![image](https://user-images.githubusercontent.com/36766101/227852700-c3b9d1cc-7099-40dd-9329-600befce806e.png)
![image](https://user-images.githubusercontent.com/36766101/227853999-aa2bbadc-4592-4ce6-beae-d8f526bd1dc6.png)
![image](https://user-images.githubusercontent.com/36766101/227854435-b5320115-6a21-4e93-82b5-3647143d8c01.png)
![image](https://user-images.githubusercontent.com/36766101/227855014-009573ff-e2e6-4f1d-ac99-3c66b49a9ccf.png)
![image](https://user-images.githubusercontent.com/36766101/227855465-b7bf2fcb-3189-4ea8-8a0b-30c1c743767d.png)
![image](https://user-images.githubusercontent.com/36766101/227855583-6148c1b0-fe9c-4ef7-b362-cbbf3acb65c6.png)
![image](https://user-images.githubusercontent.com/36766101/227855686-ba394e9d-8ad4-45ef-b4ac-03114488f9e4.png)
![image](https://user-images.githubusercontent.com/36766101/227855868-a7242697-ff1c-4853-948d-e5ebafb468ff.png)
![image](https://user-images.githubusercontent.com/36766101/227856297-a46fba77-4ce3-4f54-bfec-a3a3473b7f79.png)
![image](https://user-images.githubusercontent.com/36766101/227856365-979c232c-bfa8-45c5-818c-0144cab4fbd1.png)
![image](https://user-images.githubusercontent.com/36766101/227856532-67cd2df6-30af-446c-9537-11e50420ead3.png)
![image](https://user-images.githubusercontent.com/36766101/227856771-fb2d3000-b571-4022-b24a-ef1a9d3e9c0d.png)
![image](https://user-images.githubusercontent.com/36766101/227873406-290323df-48ef-4aff-8b70-3f1477a628d2.png)
![image](https://user-images.githubusercontent.com/36766101/227873604-c01838b6-3e14-4682-9754-7b013c1e545d.png)
![image](https://user-images.githubusercontent.com/36766101/227874024-c478bfe8-850e-4b80-8f71-3a459e91b367.png)
![image](https://user-images.githubusercontent.com/36766101/227874963-dc382307-31ae-4b12-b5d9-20d44fd19ce3.png)
![image](https://user-images.githubusercontent.com/36766101/227875390-df86fdd7-eb30-44f9-b03d-d4df1c624275.png)
![image](https://user-images.githubusercontent.com/36766101/227893648-a1114a15-49f9-404c-9056-bd8ff8169a66.png)
![image](https://user-images.githubusercontent.com/36766101/227897863-63c2412f-b9b7-4603-b949-038192bcbbae.png)
![image](https://user-images.githubusercontent.com/36766101/227898903-bf1b35f5-8320-4310-be7f-988f3ec26222.png)
![image](https://user-images.githubusercontent.com/36766101/227900963-5e3b485d-0dbf-4995-860f-eb00e821c1b9.png)
![image](https://user-images.githubusercontent.com/36766101/227901833-56fd6c25-71a1-4259-943f-a3fe53247d2a.png)
![image](https://user-images.githubusercontent.com/36766101/227901984-bcc1fe21-f15a-4bb4-90f8-7e07a871214a.png)
![image](https://user-images.githubusercontent.com/36766101/229417166-c44890c1-ba99-4f26-b75a-280491f09b08.png)
![image](https://user-images.githubusercontent.com/36766101/229417655-285069ce-b639-426d-8c86-a1eea0ead4b1.png)
![image](https://user-images.githubusercontent.com/36766101/229417887-cd893b08-4d2b-4cac-b614-6c4518c772d4.png)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/7b09c645-806b-4cec-9908-910396d84f14)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/5f1081c0-6d7c-4664-942f-4fe344f785ee)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/f002afac-2ee5-4b27-9840-5c34c8495387)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/221ab7d5-dfa9-44ef-b7c7-5b9c7324f007)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/f446c352-82ba-48c6-8fc2-6fa41e3c011e)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/d05fb141-ab77-4455-86e9-9697d43085f0)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/f361d1bb-f887-47a0-a60d-83f419503021)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/e61b7285-e83c-47a2-885b-5e67cdc068cc)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/5dc24bcb-6ae0-4474-ae3a-918b058980ee)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/01db15cd-e37c-45f6-896a-efb14356b954)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/445627cd-d4d7-49e0-b9c3-cf5943e22df0)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/248bf1f1-62fa-4447-ac25-a6f00db0a3cf)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/46eda318-4753-4238-9189-3d9bdcef357a)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/0ea901a9-8a4d-41a3-a7d8-8ec2812b8524)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/ade4c95c-3055-4b99-b95b-1dcc09bac79b)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/b1c1f41d-7ea0-463a-bed9-417f0bc51925)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/f399d877-6a83-4ea5-9fa5-73c6381c21ee)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/96e6c2d7-20b4-471a-b7e9-31d832f39a71)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/22a20759-0e84-47b7-b964-dd9ec05d6e36)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/34d4e117-2c48-4a4f-a305-d133992cf951)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/d822c527-53af-4257-b9e2-956ddc8e4e32)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/f4277858-eb17-434b-9057-d03db11947c2)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/b1b47289-c893-422f-92c7-2f28d7e6e673)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/63b55a6d-45c1-444a-adb0-d07880d7700b)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/dee03df4-2239-44b9-861c-e419d2231408)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/4e13e361-1a57-4b10-b828-69796feec46f)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/5f93df76-9222-43ed-955c-f6b6157db628)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/0b512627-b072-4dff-9f4b-77a9d7a4c7f5)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/2be63fa7-b72f-444a-beeb-f76eef027d6c)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/2886f854-9c1d-4f29-b652-fc76c47e58b5)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/e429d389-e83b-46f7-a8bc-5844b40e3d4f)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/e3a9b266-1e44-4e9c-80f8-5890ee52e526)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/ed9a657d-3e6e-4bfe-96ea-bb5c9340189b)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/ac2841fb-02ee-4b8b-a708-f35c0ebb362c)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/83ddc75a-6981-4ef8-a56f-af5bb1381d51)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/c7396790-c6bf-4b2b-99d3-bdf6658e79b7)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/88e86289-d6a8-4593-96cc-46ec4ab8e420)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/257e725b-fbec-4430-a83d-d65d45960cd2)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/6a029998-7cfd-42fb-a99d-55c10a67aaa1)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/f4a97ab0-1f0b-4f68-b39d-d552a7b218ec)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/21555d88-f6b8-4bab-bf36-21b1a482c884)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/6f81fbe1-5b7c-4ae8-bca8-b47eadad0e39)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/ba28d18c-aa4c-4d01-a602-29f1498b9986)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/b45f70a1-ef00-40ad-ab15-6e794a702fe0)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/861736ac-fe61-4f35-9b92-c208c3979b3e)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/30ee913d-e345-4166-be1e-693af957d6c3)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/9e765778-0a5d-4388-88fc-5402c4f21b66)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/f764e442-b732-4da2-a6ff-b33a546920e7)
![image](https://github.com/xiongye77/AWS_security_specialty/assets/36766101/deb27936-0afa-4d6e-899d-3a73adf4123e)


