# AWS_security_specialty


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



# Cognito user pool and identity pool

![image](https://github.com/user-attachments/assets/2d49fe29-dd13-4a98-bf3c-fb45f066b1a4)
![image](https://github.com/user-attachments/assets/6298c9a0-9eb2-4fd3-b69d-5331a393a526)
![image](https://github.com/user-attachments/assets/ed255cf9-dcfe-4030-bbd4-9d07cab6e04c)
![image](https://github.com/user-attachments/assets/f032a01f-1617-4e6a-980a-1f005714d35a)
![image](https://github.com/user-attachments/assets/55c7f914-794e-4478-b21b-1572fd7a3c8e)

for a mobile application. In this situation, you can leverage Amazon Cognito identity pools to obtain temporary AWS credentials to access the AWS services or resources you need. Cognito identity pools act as an identity federation mechanism to exchange the credentials that you provide, either from AWS or third-party identity providers (including social identity providers such as Google, Apple, Amazon, etc.), in the form of an OIDC token or a SAML assertion with temporary AWS credentials.



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


