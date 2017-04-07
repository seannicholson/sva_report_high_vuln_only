# SVA Report High Vulnerabilities


Disclaimer: This script is provided as is. USE AT YOUR OWN RISK.
NOT A SUPPORTED SOLUTION

# Configure
To configure script add API Key information to cloudpassage.yml File
>key_id: your_api_key_id

>secret_key: your_api_secret_key


# Requirements

This script requires Python 2.7.10 or greater
This script requires the CloudPassage Python SDK
> pip install cloudpassage

Install from pip with pip install cloudpassage. If you want to make modifications to the SDK you can install it in editable mode by downloading the source from this github repo, navigating to the top directory within the archive and running pip install -e . (note the . at the end). Or you can visit https://github.com/cloudpassage/cloudpassage-halo-python-sdk to clone it directly from our github.

# Dependencies 
Part of the script assumes you have labeled your servers with AWS account information to properly obtain the AWS Instance ID and AWS Account ID. The script checks for this server label ("awsAccountID_awsInstanceID"), but only makes this check if the EC2 metadata is not present in the server details JSON.


# License

Copyright (c) 2017, CloudPassage, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution. * Neither the name of the CloudPassage, Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CLOUDPASSAGE, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED ANDON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
