import os
import datetime
from time import sleep
from typing import Optional, List, Union, Dict
import boto3
import pytz as pytz
from boto3_type_annotations.iam import Client as IAMClient
from boto3_type_annotations.ses import Client as SESClient
import logging


LOGGER = logging.getLogger()
LOGGER.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

iam_client: IAMClient = boto3.client('iam')
ses_client: SESClient = boto3.client('ses')

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%z'
NOW = datetime.datetime.now(tz=pytz.utc)

PROPERTIES: Dict[str, Union[str, List[datetime.timedelta], datetime.timedelta, bool]] = {
    'alert_on_disable': True
}


class AccessKey:
    def __init__(self, id: str, username: str, created: datetime.datetime, status: str, last_used: Optional[datetime.datetime]):
        self.id = id
        self.username = username
        self.created = created
        self.status = status
        self.last_used = last_used

    def get_time_since_last_used(self) -> Optional[datetime.timedelta]:
        if self.status == 'Inactive':
            return None
        if self.last_used:
            return NOW - self.last_used
        else:
            return NOW - self.created

    def disable_credential(self):
        iam_client.update_access_key(UserName=self.username, AccessKeyId=self.id, Status='Inactive')

    def __str__(self):
        return str(vars(self))

    def __repr__(self):
        return str(vars(self))


class User:
    def __init__(self, id: str, created: datetime.datetime, email: str):
        self.id = id
        self.created = created
        self.email = email
        self.access_keys: List[AccessKey] = []
        self.console_enabled: Optional[bool] = None
        self.last_console_login: Optional[datetime.datetime] = None

    def get_time_since_last_used(self) -> Optional[datetime.timedelta]:
        if not self.console_enabled:
            return None
        if self.last_console_login:
            return NOW - self.last_console_login
        else:
            return NOW - self.created

    def disable_credential(self):
        try:
            iam_client.delete_login_profile(UserName=self.id)
        except Exception as e:
            if f'Login Profile for User {self.id} cannot be found' not in str(e):
                raise e

    def __str__(self):
        return str(vars(self))

    def __repr__(self):
        return str(vars(self))


def check_credential(credential: Union[User, AccessKey]) -> Dict[str, Optional[str]]:
    age = credential.get_time_since_last_used()
    if not age:
        return {'result': None, 'threshold': None}

    if age > PROPERTIES['disable_threshold']:
        LOGGER.info(f'Age {age} exceeds the disable threshold')
        return {'result': 'disable', 'threshold': PROPERTIES['disable_threshold'].days}
    else:
        for t in PROPERTIES['alert_thresholds']:
            if age > t:
                LOGGER.info(f'Age {age} exceeds alert threshold {t}')
                return {'result': 'alert', 'threshold': t.days}

    return {'result': None, 'threshold': None}


def process_credentials(user: User):
    """
    Find all credentials for the user to alert and / or disable, and take action on them.
    :param user:
    :return:
    """

    credentials_to_disable = []
    disabled_credentials = []
    credentials_to_alert = []

    console_result = check_credential(user)
    obj = {'credential': user, 'id': 'Console password', 'threshold': console_result['threshold']}
    if console_result['result'] == 'disable':
        credentials_to_disable.append(obj)
    elif console_result['result'] == 'alert':
        credentials_to_alert.append(obj)

    for key in user.access_keys:
        result = check_credential(key)
        obj = {'credential': key, 'id': f'Access key {key.id}', 'threshold': result['threshold']}
        if result['result'] == 'disable':
            credentials_to_disable.append(obj)
        elif result['result'] == 'alert':
            credentials_to_alert.append(obj)

    if not credentials_to_alert and not credentials_to_disable:
        LOGGER.info(f'No action required for {user.id}')
        return

    if credentials_to_alert:
        send_alerts(user, credentials_to_alert)

    if credentials_to_disable:
        for cred in credentials_to_disable:
            try:
                cred['credential'].disable_credential()
                LOGGER.info(f'Successfully disabled {cred["id"]}')
                disabled_credentials.append(cred)
            except:
                LOGGER.error(f'Error disabling credential for {user.id}', exc_info=True)

    if disabled_credentials and PROPERTIES['alert_on_disable']:
        send_disabled_alerts(user, disabled_credentials)


def send_alerts(user, credentials_to_alert):
    one = len(credentials_to_alert) == 1
    credentials_str = 'credential' if one else 'credentials'
    subject = f'Action required: inactive {credentials_str} in AWS account {PROPERTIES["account_alias"]}'
    threshold_days = PROPERTIES['disable_threshold'].days
    days_str = 'day' if threshold_days == 1 else 'days'
    body = f'''
You have {len(credentials_to_alert)} inactive {credentials_str} in the AWS account {PROPERTIES['account_alias']}:

'''

    for cred in credentials_to_alert:
        cred_days = cred['threshold']
        cred_days_str = 'day' if cred_days == 1 else 'days'
        body += f'- {cred["id"]} - unused for {cred_days} {cred_days_str}\n'

    body += f'''
The {credentials_str} above will be disabled if {'it' if one else 'they'} {'remains' if one else 'remain'} inactive after {threshold_days} {days_str}.
'''

    LOGGER.info(f'Sending alert email to {user.id}')
    LOGGER.info(f'Subject: {subject}')
    LOGGER.info(body)
    send_email(subject, body, user)


def send_disabled_alerts(user, credentials_to_alert):
    one = len(credentials_to_alert) == 1
    was = 'was' if one else 'were'
    credentials_str = 'credential' if one else 'credentials'
    subject = f'Your inactive {credentials_str} in AWS account {PROPERTIES["account_alias"]} {was} disabled'
    threshold_days = PROPERTIES['disable_threshold'].days
    days_str = 'day' if threshold_days == 1 else 'days'
    body = f'''
You have {len(credentials_to_alert)} {credentials_str} in the AWS account {PROPERTIES['account_alias']} that {was} inactive for {threshold_days} {days_str} and {was} disabled:

'''

    for cred in credentials_to_alert:
        body += f'- {cred["id"]}\n'

    body += f'''
Please contact an administrator to re-enable your access.
'''

    LOGGER.info(f'Sending disable alert email to {user.id}')
    LOGGER.info(f'Subject: {subject}')
    LOGGER.info(body)
    send_email(subject, body, user)


def send_email(subject, body, user: User):
    ses_client.send_email(
        Destination={'ToAddresses': [user.email]},
        Message={
            'Body': {
                'Text': {
                    'Charset': 'UTF-8',
                    'Data': body
                }
            },
            'Subject': {
                'Charset': 'UTF-8',
                'Data': subject
            }
        },
        Source=PROPERTIES['email_sender']
    )


def init():
    errors = []

    if 'SKIP_TAG' in os.environ:
        value = os.environ['SKIP_TAG']
        parts = value.split('=')
        if len(parts) != 2 or len(parts[0]) == 0 or len(parts[1]) == 0:
            errors.append('SKIP_TAG must be in format "TagName=TagValue"')
        else:
            LOGGER.info(f'Skip tag: {value}')
            PROPERTIES['skip_tag_key'] = parts[0]
            PROPERTIES['skip_tag_value'] = parts[1]
    else:
        LOGGER.info('SKIP_TAG not found; processing all users')

    if 'SELECTION_TAG_NAME' not in os.environ:
        errors.append('SELECTION_TAG_NAME not found; cannot proceed. It is required to ensure service accounts are not accidentally processed')
    else:
        value = os.environ.get('SELECTION_TAG_NAME')
        if not value:
            errors.append('SELECTION_TAG_NAME specified but has no value')
        LOGGER.info(f'Selection tag: {value}')
        PROPERTIES['selection_tag'] = value

    if 'EMAIL_TAG_NAME' not in os.environ:
        errors.append('EMAIL_TAG_NAME not found; cannot proceed. It is required to ensure service accounts are not accidentally processed')
    else:
        value = os.environ.get('EMAIL_TAG_NAME')
        if not value:
            errors.append('EMAIL_TAG_NAME specified but has no value')
        LOGGER.info(f'Email tag: {value}')
        PROPERTIES['email_tag'] = value

    if 'ALERT_THRESHOLDS' not in os.environ:
        errors.append('ALERT_THRESHOLDS not found; cannot proceed. Enter at least one alert threshold, separated by commas, or enter NONE to explicitly skip alerting')
    else:
        value = os.environ.get('ALERT_THRESHOLDS')
        if value == 'NONE':
            PROPERTIES['alert_thresholds'] = []
        else:
            try:
                values = [int(i.strip()) for i in value.split(',')]
                LOGGER.info(f'Alert thresholds: {values}')
                PROPERTIES['alert_thresholds'] = sorted([datetime.timedelta(days=i) for i in values], reverse=True)
            except:
                errors.append('Invalid number in ALERT_THRESHOLD; values must be integer(s) separated by commas')

    if 'DISABLE_THRESHOLD' not in os.environ:
        errors.append('DISABLE_THRESHOLD not found; cannot proceed')
    else:
        try:
            value = int(os.environ.get('DISABLE_THRESHOLD').strip())
            LOGGER.info(f'Disable threshold: {value}')
            threshold = datetime.timedelta(days=value)
            PROPERTIES['disable_threshold'] = threshold
            if [t for t in PROPERTIES['alert_thresholds'] if t >= threshold]:
                errors.append('Invalid DISABLE_THRESHOLD; must be greater than all alert thresholds')
        except:
            errors.append('Invalid DISABLE_THRESHOLD; value must be an integer')

    alert_on_disable = os.environ.get('ALERT_ON_DISABLE', '')
    if alert_on_disable.lower() == 'true':
        PROPERTIES['alert_on_disable'] = True

    if 'EMAIL_SENDER' not in os.environ:
        errors.append('EMAIL_SENDER not found; cannot proceed')
    else:
        value = os.environ.get('EMAIL_SENDER')
        if not value:
            errors.append('EMAIL_SENDER specified but has no value')
        LOGGER.info(f'Email sender: {value}')
        PROPERTIES['email_sender'] = value

    if 'ACCOUNT_ALIAS' in os.environ:
        PROPERTIES['account_alias'] = os.environ.get('ACCOUNT_ALIAS')
    else:
        PROPERTIES['account_alias'] = boto3.client('sts').get_caller_identity().get('Account')
    LOGGER.info(f'Account alias {PROPERTIES["account_alias"]}')

    return errors


def process_user_response(response, user_map):
    """
    Process a list_users response and find users that need to be processed based on tag filters.
    :param response:
    :param user_map:
    :return:
    """
    for u in response['Users']:
        username = u['UserName']
        email = None
        process = False
        tags = iam_client.list_user_tags(UserName=username)
        for tag in tags['Tags']:
            if tag['Key'] == PROPERTIES['email_tag']:
                email = tag['Value']
            if 'skip_tag_key' in PROPERTIES and tag['Key'] == PROPERTIES['skip_tag_key'] and tag['Value'] == PROPERTIES['skip_tag_value']:
                process = False  # explicitly set to false to be safe and then break so we know it sticks
                break
            if tag['Key'] == PROPERTIES['selection_tag']:
                process = True

        if not process:
            LOGGER.info(f'User {username} had the skip tag set, or the selection tag was not found; skipping user')
            continue
        if not email:
            LOGGER.warning(f'User {username} should be included, but has no email tag ({PROPERTIES["email_tag"]}), so will be skipped')
            continue

        user = User(username, u['CreateDate'], email)
        user_map[username] = user


# entrypoint for lambda
def handler(event, context):
    errors = init()

    if errors:
        LOGGER.error(f'One or more error(s) found during initialization: {"; ".join(errors)}. Exiting.')
        return

    # The initial user response will contain some basic user data - username, email, creation date
    # And we can also use the tags to perform filtering
    user_map = {}
    res = iam_client.list_users()
    process_user_response(res, user_map)

    while res['IsTruncated']:
        res = iam_client.list_users(Marker=res['Marker'])
        process_user_response(res, user_map)

    # Augment with additional acess key data. Since there are APIs for this, we'll use these so it's real time,
    # unlike the credential report.
    for username, user in user_map.items():
        res = iam_client.list_access_keys(UserName=username)
        for access_key in res['AccessKeyMetadata']:
            last_used_res = iam_client.get_access_key_last_used(AccessKeyId=access_key['AccessKeyId'])
            last_used = last_used_res['AccessKeyLastUsed'].get('LastUsedDate')
            key = AccessKey(access_key['AccessKeyId'], username, access_key['CreateDate'], access_key['Status'],
                            last_used)
            user.access_keys.append(key)

    # Generate a report and wait for it to complete (if a recent report exists, this will break the loop immediately)
    while True:
        res = iam_client.generate_credential_report()
        if res['State'] == 'COMPLETE':
            break
        sleep(10)

    res = iam_client.get_credential_report()
    content = str(res['Content'], 'utf-8')

    lines = [line.split(',') for line in content.split('\n')]

    header = {}
    for i in range(0, len(lines[0])):
        header[lines[0][i]] = i

    for row in lines[1:]:
        username = row[header['user']]
        if username not in user_map:
            continue
        user = user_map[username]

        user.created = datetime.datetime.strptime(row[header['user_creation_time']], DATE_FORMAT)
        user.console_enabled = row[header['password_enabled']].lower() == 'true'
        if user.console_enabled:
            last_used = row[header['password_last_used']]
            user.last_console_login = None if last_used == 'no_information' else datetime.datetime.strptime(last_used, DATE_FORMAT)

    # Now we can actually process the users
    for user in user_map.values():
        LOGGER.info(f'Processing {user.id}')
        process_credentials(user)

