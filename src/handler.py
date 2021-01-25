import os
import datetime
from time import sleep
from typing import Optional, List, Union, Dict, Tuple
import boto3
import pytz
from boto3_type_annotations.iam import Client as IAMClient
from boto3_type_annotations.ses import Client as SESClient
from boto3_type_annotations.dynamodb import Client as DDBClient
import logging


LOGGER = logging.getLogger()
LOGGER.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

iam_client: IAMClient = boto3.client('iam')
ses_client: SESClient = boto3.client('ses')
ddb_client: DDBClient = boto3.client('dynamodb')

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%z'
NOW = datetime.datetime.now(tz=pytz.utc)


class Properties:
    alert_on_disable = True
    skip_tag_name: Optional[str] = None
    skip_tag_value: Optional[str] = None
    selection_tag: str
    email_tag: str
    alert_thresholds: List[datetime.timedelta]
    disable_threshold: datetime.timedelta
    email_sender: str
    account_alias: str
    dynamo_db_table: str


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


def check_credential(credential: Union[User, AccessKey], saved_user) -> Dict[str, Optional[str]]:
    age = credential.get_time_since_last_used()
    if not age:  # indicates cred is already inactive; do nothing
        return {'result': None, 'threshold': None}

    # get the last threshold that this credential exceeded to generate an alert (-1 means there is no alert history)
    last_alert = -1
    if saved_user:
        saved_cred_key = 'console_password' if type(credential) == User else credential.id
        cred_state = saved_user['credentials']['M']
        if saved_cred_key in cred_state:
            last_alert = int(cred_state[saved_cred_key]['M']['last_alert']['N'])
        LOGGER.info(f'Credential {saved_cred_key} last exceeded threshold: {last_alert} days')

    if age > Properties.disable_threshold:
        LOGGER.info(f'Age {age} exceeds the disable threshold')
        return {'result': 'disable', 'threshold': Properties.disable_threshold.days}
    else:
        # iterate the thresholds, which are sorted from high to low (so the first one that is exceeded is the one we
        # potentially need to alert on - if we started low to high, we'd have to check until we found one that was NOT
        # exceeded)
        for t in Properties.alert_thresholds:
            if age > t and t.days > last_alert:
                LOGGER.info(f'Age {age} exceeds alert threshold {t}')
                return {'result': 'alert', 'threshold': t.days}
            elif age > t and t.days <= last_alert:
                LOGGER.info(f'Age {age} exceeds alert threshold {t}, but this was already alerted')
                return {'result': 'already_alerted', 'threshold': t.days}

    return {'result': None, 'threshold': None}


def process_credentials(user: User, saved_user):
    """
    Find all credentials for the user to alert and / or disable, and take action on them.

    saved_user should be the state for this user in the state storage, or None of this user is not present in the storage.
    """

    # we'll populate this only with credentials that get alerts. this means if a credential is not present
    # this will make it easy to determine whether to send an alert
    ret_user = {
        'credentials': {},
        'username': user.id
    }

    credentials_to_disable = []
    disabled_credentials = []
    credentials_to_alert = []

    console_result = check_credential(user, saved_user)
    obj = {'credential': user, 'id': 'Console password', 'threshold': console_result['threshold']}
    if console_result['result'] == 'disable':
        credentials_to_disable.append(obj)
    elif console_result['result'] == 'alert':
        credentials_to_alert.append(obj)
        ret_user['credentials']['console_password'] = {'last_alert': obj['threshold']}
    elif console_result['result'] == 'already_alerted':
        ret_user['credentials']['console_password'] = {'last_alert': obj['threshold']}

    key_num = 1  # display the key number instead of the actual key
    for key in user.access_keys:
        result = check_credential(key, saved_user)
        obj = {'credential': key, 'id': f'Access key #{key_num}', 'threshold': result['threshold']}
        if result['result'] == 'disable':
            credentials_to_disable.append(obj)
        elif result['result'] == 'alert':
            credentials_to_alert.append(obj)
            ret_user['credentials'][key.id] = {'last_alert': obj['threshold']}
        elif result['result'] == 'already_alerted':
            ret_user['credentials'][key.id] = {'last_alert': obj['threshold']}

        key_num += 1

    if not credentials_to_alert and not credentials_to_disable:
        LOGGER.info(f'No action required for {user.id}')
        return ret_user

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

    if disabled_credentials and Properties.alert_on_disable:
        send_disabled_alerts(user, disabled_credentials)

    return ret_user


def send_alerts(user, credentials_to_alert):
    one = len(credentials_to_alert) == 1
    credentials_str = 'credential' if one else 'credentials'
    subject = f'Action required: inactive {credentials_str} in AWS account {Properties.account_alias}'
    threshold_days = Properties.disable_threshold.days
    days_str = 'day' if threshold_days == 1 else 'days'
    body = f'''
You have {len(credentials_to_alert)} inactive {credentials_str} in the AWS account {Properties.account_alias}:

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
    subject = f'Your inactive {credentials_str} in AWS account {Properties.account_alias} {was} disabled'
    threshold_days = Properties.disable_threshold.days
    days_str = 'day' if threshold_days == 1 else 'days'
    body = f'''
You have {len(credentials_to_alert)} {credentials_str} in the AWS account {Properties.account_alias} that {was} inactive for {threshold_days} {days_str} and {was} disabled:

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
        Source=Properties.email_sender
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
            Properties.skip_tag_name = parts[0]
            Properties.skip_tag_value = parts[1]
    else:
        LOGGER.info('SKIP_TAG not found; processing all users')

    res = get_required_string('SELECTION_TAG_NAME')
    if res[0]:
        Properties.selection_tag = res[1]
    else:
        errors.append(res[1])

    res = get_required_string('EMAIL_TAG_NAME')
    if res[0]:
        Properties.email_tag = res[1]
    else:
        errors.append(res[1])

    res = get_required_string('ALERT_THRESHOLDS')
    if res[0]:
        if res[1] == 'NONE':
            Properties.alert_thresholds = []
        else:
            try:
                values = [int(i.strip()) for i in res[1].split(',')]
                LOGGER.info(f'Alert thresholds: {values}')
                Properties.alert_thresholds = sorted([datetime.timedelta(days=i) for i in values], reverse=True)
            except:
                errors.append('Invalid number in ALERT_THRESHOLD; values must be integer(s) separated by commas')
    else:
        errors.append(res[1])

    res = get_required_int('DISABLE_THRESHOLD')
    if res[0]:
        threshold = datetime.timedelta(days=res[1])
        Properties.disable_threshold = threshold
        if [t for t in Properties.alert_thresholds if t >= threshold]:
            errors.append('Invalid DISABLE_THRESHOLD; must be greater than all alert thresholds')
    else:
        errors.append(res[1])

    alert_on_disable = os.environ.get('ALERT_ON_DISABLE', '')
    if alert_on_disable.lower() == 'true':
        Properties.alert_on_disable = True

    res = get_required_string('EMAIL_SENDER')
    if res[0]:
        Properties.email_sender = res[1]
    else:
        errors.append(res[1])

    if 'ACCOUNT_ALIAS' in os.environ:
        Properties.account_alias = os.environ.get('ACCOUNT_ALIAS')
    else:
        Properties.account_alias = boto3.client('sts').get_caller_identity().get('Account')
    LOGGER.info(f'Account alias {Properties.account_alias}')

    res = get_required_string('DYNAMO_TABLE_NAME')
    if res[0]:
        Properties.dynamo_db_table = res[1]
    else:
        errors.append(res[1])

    return errors


def get_required_string(arg_name) -> Tuple[bool, str]:
    """
    Retrieves the specified argument from the environment, or an error message if the argument doesn't exist.
    The returned tuple includes a bool indicating whether the return value is the argument value or an error message.
    True indicates the argument was found, False indicates an error.
    :param arg_name:
    :return:
    """
    if arg_name not in os.environ:
        return False, f'{arg_name} not found; cannot proceed'
    else:
        value = os.environ.get(arg_name)
        if not value:
            return False, f'{arg_name} specified but has no value'
        value = value.strip()
        LOGGER.info(f'{arg_name}: {value}')
        return True, value


def get_required_int(arg_name) -> Tuple[bool, Union[int, str]]:
    """
    Retrieves the specified argument from the environment, or an error message if the argument doesn't exist or is not an integer.
    The returned tuple includes a bool indicating whether the return value is the argument value or an error message.
    True indicates the argument was found, False indicates an error.
    :param arg_name:
    :return:
    """
    res = get_required_string(arg_name)
    if not res[0]:
        return res
    else:
        try:
            return True, int(res[1])
        except:
            return False, f'Invalid {arg_name}; value must be an integer'


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
            if tag['Key'] == Properties.email_tag:
                email = tag['Value']
            if Properties.skip_tag_name and tag['Key'] == Properties.skip_tag_name and tag['Value'] == Properties.skip_tag_value:
                process = False  # explicitly set to false to be safe and then break so we know it sticks
                break
            if tag['Key'] == Properties.selection_tag:
                process = True

        if not process:
            LOGGER.info(f'User {username} had the skip tag set, or the selection tag was not found; skipping user')
            continue
        if not email:
            LOGGER.warning(f'User {username} should be included, but has no email tag ({Properties.email_tag}), so will be skipped')
            continue

        user = User(username, u['CreateDate'], email)
        user_map[username] = user


def get_state_from_dynamo():
    users = {}
    res = ddb_client.scan(TableName=Properties.dynamo_db_table, Limit=1)
    for u in res['Items']:
        username = u['username']['S']
        users[username] = u

    while 'LastEvaluatedKey' in res:
        res = ddb_client.scan(TableName=Properties.dynamo_db_table, Limit=1, ExclusiveStartKey=res['LastEvaluatedKey'])
        for u in res['Items']:
            username = u['username']['S']
            users[username] = u

    return users


# entrypoint for lambda
def handler(event, context):
    try:
        errors = init()

        if errors:
            LOGGER.error(f'One or more error(s) found during initialization: {"; ".join(errors)}. Exiting.')
            return

        saved_users = get_state_from_dynamo()
        users_to_save = {}

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
            users_to_save[user.id] = process_credentials(user, saved_users.get(user.id))

        # now just update the saved state; also, find any saved users that we did not process now, and remove them
        users_to_remove = saved_users.keys() - users_to_save.keys()
        for username in users_to_remove:
            ddb_client.delete_item(TableName=Properties.dynamo_db_table, Key={'username': {'S': username}})

        for username, user in users_to_save.items():
            # convert to DDB JSON format (e.g., {'a': {'b': #}} becomes {'M': {'a': {'M': {'b': {'N': # }}}}}
            for cred_name, cred in user['credentials'].items():
                for attr, val in cred.items():
                    # currently we are only storing an int here, so we don't need other type checks
                    if type(val) == int:
                        cred[attr] = {'N': str(val)}

                user['credentials'][cred_name] = {'M': cred}

            user['credentials'] = {'M': user['credentials']}

            ddb_client.update_item(TableName=Properties.dynamo_db_table,
                                   Key={'username': {'S': username}},
                                   UpdateExpression='SET credentials = :val',
                                   ExpressionAttributeValues={':val': user['credentials']})

    except Exception as e:
        LOGGER.error('An unrecoverable error occurred during execution', exc_info=True)
