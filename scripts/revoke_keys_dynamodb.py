#!/usr/bin/env python3

# Until this gets put into a proper deployment model, setup to run this is:
#
# python3 -m virtualenv venv
# source venv/bin/activate
# pip install boto3

import argparse
import boto3
import json
import logging
import os
import time
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

TABLE_NAME = 'EncryptionKey'
PARTITION_KEY = 'Id'
SORT_KEY = 'Created'
KEY_RECORD = 'KeyRecord'
REVOKED = 'Revoked'
KEY_RECORD_REVOKED_FULLY_QUALIFIED = f'{KEY_RECORD}.{REVOKED}'


def revoke_envelope_key_record_by_key(table, execute_flag, id, created):
    get_response = table.get_item(
        Key={
            PARTITION_KEY: id,
            SORT_KEY: created
        },
        ProjectionExpression=KEY_RECORD # Get entire map to handle missing Revoked attribute
    )

    if get_response.get('Item'):
        logger.info(
            f'Found envelope key record for id={id}, created={created}. Revoking...'
        )


        item = get_response['Item']

        # Revoked flag may not exist so handle nil case
        if item[KEY_RECORD].get(REVOKED) and item[KEY_RECORD][REVOKED]:
            logger.warning(
                f'Envelope key record for id={id}, created={created} already revoked!'
            )

        elif execute_flag:
            table.update_item(
                Key={PARTITION_KEY: id, SORT_KEY: created},
                UpdateExpression=f'set {KEY_RECORD_REVOKED_FULLY_QUALIFIED} = :r',
                ExpressionAttributeValues={':r': True},
            )


            logger.info(
                f'Marked envelope key record for id={id}, created={created} revoked successfully!'
            )

        else:
            logger.info(
                f'DRY-RUN update_item for id={id}, created={created} and set {KEY_RECORD_REVOKED_FULLY_QUALIFIED} = True'
            )

    else:
        logger.warning(
            f'Envelope key record for id={id}, created={created} not found!'
        )


def revoke_intermediate_keys_by_created(table, execute_flag, created):
    return revoke_envelope_key_records_by_created_and_id_prefix(table, execute_flag, created, '_IK_')


def revoke_system_keys_by_created(table, execute_flag, created):
    return revoke_envelope_key_records_by_created_and_id_prefix(table, execute_flag, created, '_SK_')


def revoke_envelope_key_records_by_created_and_id_prefix(table, execute_flag, created, id_prefix):
    results = get_all_items_to_revoke(table, created, id_prefix)

    logger.info(
        f'Fetched {len(results)} rows to revoke using id_prefix={id_prefix}, created<{created}'
    )


    # Sort by created to distribute across partitions (avoid hot partitions)
    results = sorted(results, key=lambda i: i[SORT_KEY])

    if execute_flag:
        # batch_writer handles batching and sending for us automatically
        with table.batch_writer() as batch:
            for item in results:
                item[KEY_RECORD][REVOKED] = True
                batch.put_item(item)

        logger.info(f'Marked {len(results)} keys revoked successfully!')
    else:
        logger.info(
            f'DRY-RUN would have run batch_writer.put_item for {len(results)} keys'
        )


def get_all_items_to_revoke(table, created, id_prefix):
    # Build the filter expression we need
    created_before_key = Key(SORT_KEY).lt(created)
    id_prefix_key = Key(PARTITION_KEY).begins_with(id_prefix)
    not_revoked_attr = Attr(KEY_RECORD_REVOKED_FULLY_QUALIFIED).eq(False) | Attr(KEY_RECORD_REVOKED_FULLY_QUALIFIED).not_exists()
    filter_expression = created_before_key & id_prefix_key & not_revoked_attr

    results = []
    last_evaluated_key = None

    while True:
        # Get all attributes as batch write only supports replace or delete, and ExclusiveStartKey doesn't accept None so using kwargs style
        scan_args = dict(FilterExpression=filter_expression)
        if last_evaluated_key:
            scan_args['ExclusiveStartKey'] = last_evaluated_key
        scan_response = table.scan(**scan_args)

        if scan_response.get('Items'):
            results.extend(scan_response['Items'])

        # No more results, break out (do-while loop). Otherwise setup for next page
        if not scan_response.get('LastEvaluatedKey'):
            break
        else:
            last_evaluated_key = scan_response['LastEvaluatedKey']

    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Revoke script for DynamoDB metastore. NOTE: Will perform dry-run by default.')
    parser.add_argument('--execute', action='store_true',
                        help='Executes any write operations, which do not run by default (read operations always execute)')

    subparsers = parser.add_subparsers(title='actions', dest='action')
    subparsers.required = True

    single_parser = subparsers.add_parser('single', help='Revoke a single key by id and created time')
    single_parser.add_argument('--id', required=True, help='The key id')
    single_parser.add_argument('--created', required=True, type=int, help='The key created time')
    single_parser.add_argument('--table', default=TABLE_NAME, help='The table name to use')

    bulk_parser = subparsers.add_parser('bulk', help='Revoke all system or intermediate keys created before the given time. WARNING: Uses Scan API,'
                                        ' which reads the *entire* table and may potentially use up many RCUs. Avoid this if possible, e.g. revoke'
                                        ' individual system keys.')
    bulk_parser.add_argument('--created-before', required=True, type=int, help='The created time cutoff')
    bulk_parser.add_argument('--type', required=True, choices=('system', 'intermediate'), help='The type of keys to revoke')
    bulk_parser.add_argument('--table', default=TABLE_NAME, help='The table name to use')

    arguments = parser.parse_args()

    execute_flag = arguments.execute

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(TABLE_NAME)
    if arguments.action == 'single':
        revoke_envelope_key_record_by_key(table, execute_flag, arguments.id, arguments.created)
    elif arguments.type == 'system':
        revoke_system_keys_by_created(table, execute_flag, arguments.created_before)
    else:
        revoke_intermediate_keys_by_created(table, execute_flag, arguments.created_before)
