import json
import boto3
import os
from decimal import Decimal

TABLE_NAME = os.environ.get('TABLE_NAME', 'aicgqaf-reviews')
REGION = os.environ.get('AWS_REGION', 'ap-southeast-1')

def decimal_to_str(obj):
    if isinstance(obj, Decimal):
        return str(obj)
    raise TypeError

def handler(event, context):
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'GET,OPTIONS'
    }
    
    if event.get('httpMethod') == 'OPTIONS':
        return {'statusCode': 200, 'headers': headers, 'body': ''}
    
    try:
        db = boto3.resource('dynamodb', region_name=REGION)
        table = db.Table(TABLE_NAME)
        result = table.scan()
        items = result.get('Items', [])
        
        # Sort by completed_at descending
        items.sort(key=lambda x: x.get('completed_at', x.get('layer1_completed_at', '')), reverse=True)
        
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({'items': items, 'count': len(items)}, default=decimal_to_str)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'error': str(e)})
        }
