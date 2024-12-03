# AWS_security_specialty


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


