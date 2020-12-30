# -*- coding: utf-8 -*-

import os
import uuid
import json
import requests
import re
from datetime import datetime
import urllib
import hashlib
import hmac
import base64

REQUEST_URL = 'https://alidns.aliyuncs.com/'
LOCAL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ip.txt')
ALIYUN_SETTINGS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aliyun_settings.json')
DOMAIN_TYPE = 'AAAA'

def get_common_params(settings):
	"""
	获取公共参数
	参考文档：https://help.aliyun.com/document_detail/29745.html?spm=5176.doc29776.6.588.sYhLJ0
	"""
	return {
		'Format': 'json',
		'Version': '2015-01-09',
		'AccessKeyId': settings['access_key'],
		'SignatureMethod': 'HMAC-SHA1',
		'Timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
		'SignatureVersion': '1.0',
		'SignatureNonce': uuid.uuid4()
	}

def get_signed_params(http_method, params, settings):
	"""
	参考文档：https://help.aliyun.com/document_detail/29747.html?spm=5176.doc29745.2.1.V2tmbU
	"""

	#1、合并参数，不包括Signature
	params.update(get_common_params(settings))
	#2、按照参数的字典顺序排序
	sorted_params = sorted(params.items())
	#3、encode 参数
	query_params = urllib.parse.urlencode(sorted_params)
	#4、构造需要签名的字符串
	str_to_sign = http_method + "&" + urllib.parse.quote_plus("/") + "&" + urllib.parse.quote_plus(query_params)
	#5、计算签名
	signature = hmac.new((settings['access_secret'] + '&').encode('utf-8'), str_to_sign.encode('utf-8'), hashlib.sha1).digest()
	signature = base64.b64encode(signature)
	#6、将签名加入参数中
	params['Signature'] = signature

	return params

def update_yun(ip):
	"""
	修改云解析
	参考文档：
		获取解析记录：https://help.aliyun.com/document_detail/29776.html?spm=5176.doc29774.6.618.fkB0qE
		修改解析记录：https://help.aliyun.com/document_detail/29774.html?spm=5176.doc29774.6.616.qFehCg
	"""
	with open(ALIYUN_SETTINGS, 'r') as f:
		settings = json.loads(f.read())

	#首先获取解析列表
	domain = settings['domain']
	root_domain = domain[domain.find('.') + 1 :]
	sub_domain = domain[: domain.find('.')]
	print('root domain is ' + root_domain + ', sub domain is ' + sub_domain)

	get_params = get_signed_params('GET', {
		'Action': 'DescribeDomainRecords',
		'DomainName': root_domain,
		'TypeKeyWord': DOMAIN_TYPE
	}, settings)

	get_resp = requests.get(REQUEST_URL, get_params)

	records = get_resp.json()
	print('============ get_records ============')
	print(records)
	for record in records['DomainRecords']['Record']:
		if record['RR'] != sub_domain:
			continue
		post_params = get_signed_params('POST', {
			'Action': 'UpdateDomainRecord',
			'RecordId': record['RecordId'],
			'RR': record['RR'],
			'Type': record['Type'],
			'Value': ip
		}, settings)
		post_resp = requests.post(REQUEST_URL, post_params)
		result = post_resp.json()
		print('============ update_record ============')
		print(result)

def get_curr_ip():
	rsp = requests.get('https://api6.my-ip.io/ip')
	return rsp.text

def get_lastest_local_ip():
	"""
	获取最近一次保存在本地的ip
	"""
	print('ip local path', LOCAL_FILE)

	fmod = 'r'
	if not os.path.exists(LOCAL_FILE):
		fmod='w+'
	with open(LOCAL_FILE, fmod) as f:
		last_ip = f.readline()
	return last_ip

if __name__ == '__main__':
	ip = get_curr_ip()
	if not ip:
		print('get ip failed')
	else:
		last_ip = get_lastest_local_ip()
		print(ip, last_ip)
		if ip != last_ip:
			print('save ip to {}...'.format(LOCAL_FILE))
			with open(LOCAL_FILE, 'w') as f:
				f.write(ip)
			print('update remote record...')
			update_yun(ip)
