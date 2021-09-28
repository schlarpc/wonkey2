# wonkey2

## What is it?

Personal image host and file server on AWS, specifically designed to interoperate with ShareX.

## Features

* Fronted by the CloudFront CDN and backed by Amazon S3 storage
* Easy deployment with one self-contained CloudFormation template
* Serverless architecture with no fixed costs; only pay for requests, data stored, and egress bandwidth
* Data encrypted at rest with key material only made available to the uploader
* Supports files up to 5GiB in size
* Configurable data retention/expiration
* Supports custom domain names with automatic certificate issuance and Route 53 DNS configuration
* Personalize your server with a custom redirect on the server index
* Custom ShareX destination configuration available at `/sharex.json`
* RFC 6266 HTTP header support for preserving original filenames
* HTTP byte range header support for efficient video streaming
* Flexible URLs; you can append arbitrary file extensions or paths to uploaded URLs
  * e.g. `/hQ9W6Jm`, `/hQ9W6Jm.png`, and `/hQ9W6Jm/whatever.png` all point to the same file

## How much does it cost to run?

Some rough numbers based on current AWS pricing:

* CloudFront requests - $0.000001 / request
* CloudFront bandwidth - $0.085 / GiB
* Lambda@Edge requests - $0.00000120 / request
* Lambda@Edge runtime - $0.0000000375075 / request
* S3 GET requests - $0.000004 / request
* S3 storage - $0.023 / GiB / month
  * $0.0125 / GiB / month after 30 days of inactivity on files larger than 128KiB
* S3 tiering management - $0.0000025 / file / month larger than 128KiB

Additional fixed monthly charges apply for Route 53 hosted zones if you choose to use one;
this template integrates with Route 53 but does not create any hosted zones.
