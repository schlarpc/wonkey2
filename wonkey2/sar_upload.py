import subprocess

import boto3


def main():
    sar = boto3.client('serverlessrepo', region_name='us-east-1')

    application_details = {
        'Author': 'Chaz Schlarp',
        'Description': 'Simple image and file host for use with ShareX',
        'HomePageUrl': 'https://github.com/schlarpc/wonkey2',
        'Labels': ['s3', 'cloudfront', 'sharex'],
        'ReadmeBody': open('README.md', 'r').read(),
    }

    application_name = 'wonkey2'
    for application in sar.get_paginator("list_applications").paginate().search('Applications[]'):
        if application["Name"] == application_name:
            application_id = application["ApplicationId"]
            break
    else:
        response = sar.create_application(
            **application_details,
            Name=application_name,
            LicenseBody=open('LICENSE', 'r').read(),
            SpdxLicenseId='MIT',
        )
        application_id = response["ApplicationId"]

    process = subprocess.run(["git", "describe", "--tags"], check=True, capture_output=True, encoding='utf-8')
    current_tag = process.stdout.strip()

    try:
        sar.create_application_version(
            ApplicationId=application_id,
            SemanticVersion='1.0.0-' + current_tag,
            TemplateBody=open('template.json', 'r').read(),
            SourceCodeUrl='https://github.com/schlarpc/wonkey2',
        )
    except sar.exceptions.ConflictException:
        print('Version already exists')

    sar.put_application_policy(
        ApplicationId=application_id,
        Statements=[
            {
                "Actions": ["Deploy"],
                "Principals": ["*"],
                "StatementId": "public-access-enabled",
            }
        ],
    )

    print(application_id)


if __name__ == "__main__":
    main()
