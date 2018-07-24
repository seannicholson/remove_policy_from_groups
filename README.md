# remove_policy

Disclaimer: This script is provided as is. USE AT YOUR OWN RISK.
NOT A SUPPORTED SOLUTION

# Configure
*Halo API Key and endpoint*
To configure script add API Key information to cloudpassage.yml File
>key_id: your_api_key_id

>secret_key: your_api_secret_key

>api_hostname: "api.cloudpassage.com"

>api_port: 443

>remove_policy_id: enter the Policy ID you are looking for in ''



# Running
*python python remove_policy.py*

# Dependencies
This script requires installation of the CloudPassage Python SDK. This script requires that you have created the AWS policy and role to grant the CloudPassage AWS account the permissions listed on the Site Administration Integrations CSP Accounts page. If you are going to use an SNS topic to forward messages to, please make sure you have configured the topic to receive messages from CloudPassage.

CloudFormation template to create the AWS IAM Policy and Role is available https://github.com/seannicholson/halo_cloudsecure_cf_template


# License

Copyright (c) 2018, CloudPassage, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution. * Neither the name of the CloudPassage, Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CLOUDPASSAGE, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED ANDON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
