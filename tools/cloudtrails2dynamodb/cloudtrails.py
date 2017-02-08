#!/bin/env python
#-*- coding: utf-8 -*-
import sys
import json
import gzip
import time
import re
import logging
import logging.config
import traceback
import decimal
import os
from io import BytesIO
import pdb

import boto3

reload(sys)
sys.setdefaultencoding('utf-8')

logging.config.fileConfig(os.path.split(os.path.realpath(__file__))[0]+"/conf/logging.conf")

logger = logging.getLogger("mylogger")


class CloudTrailProcessor(object):

    def __init__(self):
        self.__sqs = boto3.resource('sqs')
        self.__s3 = boto3.client('s3')
        self.__s3_resource = boto3.resource('s3')
        self.__dynamo = boto3.resource('dynamodb')
        self.__s3_bucket = 'bucketaudit-do-not-move'
        self.__queue_name = 'cloudtrailtest'
        self.__dynamo_table_name = 'cloudtrails_2017'

    def set_dynamo_table_name(self, table_name):
        self.__dynamo_table_name = table_name

    def refresh_history_by_s3url(self, prefix):
        bucket = self.__s3_resource.Bucket(self.__s3_bucket)
        objs = bucket.objects.filter(Prefix=prefix)
        for idx, obj in enumerate(objs):
            s3urls = [(self.__s3_bucket, obj.key)]
            logger.debug("start %s, idx: %d", obj.key, idx)
            #pdb.set_trace()
            try:
                records = self.get_cloudtrails_records(s3urls)
                logger.debug("-----myrecords-----")
                logger.debug(records)
                self.put_cloudtrails_records_2_dynamo(records)
            except Exception as e:
                logger.debug("process %s error, need retry", obj.key)
                print(e)
            logger.error("complete %s, idx: %d", obj.key, idx)

    def gen_table(self, table_name):
        table = self.__dynamo.create_table(
            TableName = table_name,
            KeySchema = [
                {
                    'AttributeName': u'事件ID',
                    'KeyType': 'HASH'
                }
            ],
            AttributeDefinitions = [
                {
                    'AttributeName': u'事件ID',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput = {
                'ReadCapacityUnits': 10,
                'WriteCapacityUnits': 10
            }
        )
        
        table.meta.client.get_waiter('table_exists').wait(TableName=table_name)
        self.__dynamo_table_name = table_name
        logger.debug('%s created OK', table_name)

    def process(self):
        while True:
            s3urls = self.get_cloudtrails_s3urls()
            records = self.get_cloudtrails_records(s3urls)
            
            try:
                self.put_cloudtrails_records_2_dynamo(records)
            except Exception as e:
                print(e)
                logger.error("==--ErrorS3Urls: %s", "!".join(["s3://%s/%s" % (b, p) for b, p in s3urls]))
            time.sleep(2)

    def __get_msgs_from_queue(self, queue):
        queue = self.__sqs.get_queue_by_name(QueueName=queue)
        msgs = queue.receive_messages()
        return msgs

    def get_cloudtrails_s3urls(self):
        msgs = self.__get_msgs_from_queue(self.__queue_name)
        s3urls = []

        for m in msgs:
            body = json.loads(m.body)
            recs = json.loads(body['Message'])
            try:
                prefix = "s3://%s/%s" % (recs['Records'][0]['s3']['bucket']['name'], recs['Records'][0]['s3']['object']['key'])
                logger.debug(prefix)
                s3urls.append((recs['Records'][0]['s3']['bucket']['name'],  recs['Records'][0]['s3']['object']['key']))
            except KeyError as e:
                print(e)

        return s3urls

    def __get_records_from_s3(self, bucket, prefix):
        #pdb.set_trace()
        output = BytesIO()
        self.__s3.download_fileobj(bucket, prefix, output)
        gzipper = gzip.GzipFile(fileobj=output)
        output.seek(0)
        data = gzipper.read()
        data = data.replace('""', '"unkown"')
        data = re.sub(r'(":\s+)(\d+(\.\d)?)(,|\})', r'\1"\2"\4', data)
        res = {}
        res['Records'] = []
        try:
            res = json.loads(data, parse_float=decimal.Decimal)
        except Exception as e:
            with open('jsonerror', 'a') as f:
                f.write(data)
                f.write(e.message)
            logger.error("======jsonerror=====")
            logger.error(e)
        return res

    def get_cloudtrails_records(self, s3urls):
        #pdb.set_trace()
        records = []
        for bucket, prefix in s3urls:
            try:
                res = self.__get_records_from_s3(bucket, prefix)
                logger.debug("new records number: %d", len(res['Records']))
            except Exception as e:
                logger.error(e)
                continue
            records.extend(res['Records'])
        logger.debug("total records in one batch: %d", len(records))
        return records

    def __put_2_dynamo(self, table_name, items):
        table = self.__dynamo.Table(table_name)
        user_identities = set(['AssumedRole', u'AWSService', u'IAMUser', u'Root']) # ['IAMUser', 'Role', '']
        logger.debug("^^^^start2dynamo")
        
        with table.batch_writer() as batch:
            for item in items:
                real_item = {}
                try:
                    real_item[u'事件ID'] = item['eventID']
                    real_item[u'事件源'] = item.get('eventSource')
                    real_item[u'事件时间'] = item.get('eventTime')
                    real_item[u'事件名称'] = item.get('eventName')
                    real_item[u'错误代码'] = item.get('errorCode', None)
                    real_item[u'AWS区域'] = item.get('awsRegion')
                    access_key_id = None
                    if item['userIdentity']['type'] == 'IAMUser':
                        access_key_id = item.get('userIdentity', {}).get('accessKeyId')
                    elif item['userIdentity']['type'] == 'AWSService': 
                        access_key_id = item.get('responseElements', {}).get('credentials', None)
                    elif item['userIdentity']['type'] == 'AssumedRole': 
                        access_key_id = item.get('userIdentity', {}).get('accessKeyId')

                    real_item[u'AWS访问秘钥'] = access_key_id
                    real_item[u'请求ID'] = item.get('requestID', None)
                    real_item[u'源IP地址'] = item.get('sourceIPAddress', None)
                    user_name = 'unkown'
                    if item['userIdentity']['type'] in ('IAMUser', 'Root'):
                        user_name = item['userIdentity']['userName']
                    elif item['userIdentity']['type'] == 'AssumedRole':
                        user_name = item['userIdentity'].get('sessionContext', {}).get('sessionIssuer', {}).get('userName', 'unkown')
                    real_item[u'用户名'] = user_name
                    real_item[u'身份类型'] = item['userIdentity']['type']
                    user_identities.add(item['userIdentity']['type'])
                    #real_item[u'RAW记录'] = json.dumps(item) 
                    #item['requestParameters'] = json.dumps(item.get('requestParameters', ''))
                    real_item[u'RAW记录'] = item
                    if item['userIdentity']['type'] == 'IAMUser':
                        logger.debug("!!!!this is a IAMUser action: %s, %s", real_item[u'用户名'], item['eventName'])
                    batch.put_item(Item=real_item)
                except Exception as e:
                    logger.error("========w2dynamodb_Exception=========")
                    logger.error(e)
                    logger.error("--------realItem---------")
                    logger.error(real_item)
                    logger.error("--------Item---------")
                    logger.error(item)
                    #batch.put_item(Item=item)
        logger.debug('%s current item count: %d', table_name, table.item_count)
        logger.debug(user_identities)

    def put_cloudtrails_records_2_dynamo(self, records):
        self.__put_2_dynamo(self.__dynamo_table_name, records)

if __name__ == '__main__':
    pro = CloudTrailProcessor()
    #pro.gen_table('cloudtrails')
    pro.set_dynamo_table_name('cloudtrails_2015')
    prefix = 'path/to/CloudTrail/history/in/s3/'
    #pro.process()
    pro.refresh_history_by_s3url(prefix)
