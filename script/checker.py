#!/usr/bin/env python3
import json
import os
import sys

import yaml
from IPy import IP


class log:
    def __init__(self):
        self.has_error = False
        self.has_warning = False

    def error(self, msg):
        self.has_error = True
        print(f'❌️ {msg}')

    def warning(self, msg):
        self.has_warning = True
        print(f'⚠️ {msg}')

    def exit(self):
        if self.has_error:
            print()
            print('请修复错误后再提交')
            exit(1)
        elif self.has_warning:
            print()
            print('请管理员合并前二次确认')
        else:
            print('✅ 校验通过')
        exit(0)


log = log()
os.chdir('as')

if len(sys.argv) > 2:
    log.error("每次 PR 仅支持修改一个文件")
    log.exit()

if sys.argv[1] == 'service.yml':
    with open('service.yml', 'r', encoding='utf8') as f:
        data = yaml.load(f, Loader=yaml.Loader)
    if len(set(i['ip'] for i in data)) != len(data):
        log.error('服务段有重复 IP')
    log.exit()

new_file = sys.argv[1][3:-4]
datas = {}
for asn in os.listdir():
    if asn.endswith('.yml') and (asn.startswith('421111') or asn.startswith('422008')):
        with open(asn, 'r', encoding='utf8') as f:
            data = yaml.load(f, Loader=yaml.Loader)
            datas[asn[:-4]] = data
flag = False
for i in ['name', 'ip']:
    if i not in datas[new_file]:
        log.error(f'缺少 `{i}` 字段')
        flag = True
if flag:
    log.exit()
if 'qq' not in datas[new_file]:
    log.warning('缺少 QQ 号')
existed_ip = {}
existed_domain = {}
for asn in datas:
    if asn == new_file:
        continue
    existed_ip.update({IP(i): asn for i in datas[asn]['ip']})
    existed_domain.update({i.lower(): asn for i in datas[asn].get('domain', {}).keys()})
if not all(i.endswith('.dn11') for i in datas[new_file].get('domain', {}).keys()):
    log.error("域名必须以 .dn11 结尾")
try:
    [IP(i) for i in datas[new_file]['ip']]
except ValueError:
    log.error("IP 格式错误")
for ip in datas[new_file]['ip']:
    for eip in existed_ip:
        if IP(ip) in eip:
            log.error(f"IP `{ip}` 已被 `{existed_ip[eip]}` 持有")
        elif eip in IP(ip):
            log.error(f"IP `{ip}` 与 `{existed_ip[eip]}` 持有的 `{eip}` 重叠")
for domain in datas[new_file].get('domain', {}):
    if domain.lower() in existed_domain:
        log.error(f"域名 `{domain}` 已被 `{existed_domain[domain.lower()]}` 持有")
    if not datas[new_file]['domain'][domain]:
        log.error(f"域名 `{domain}` 未指定 NS")
        continue
    visited = set()
    dup = [x for x in datas[new_file]['domain'][domain] if x in visited or (visited.add(x) or False)]
    if dup:
        log.error(f'NS `{", ".join(set(dup))}` 重复定义')
for ns in datas[new_file].get('ns', []):
    if not any(ns.endswith(i) for i in datas[new_file].get('domain', {})):
        log.error(f'NS 仅可由对应域名的持有者定义，您不持有 `{ns}`')
net172 = [int(str(IP(i))[:-3].split('.')[2]) for i in existed_ip if IP(i) in IP('172.16.0.0/16')]
net172.sort()
net172_new = set()
for i in datas[new_file]['ip']:
    ip = IP(i)
    reserved = [
        '10.0.0.0/24',
        '10.42.0.0/16',
        '10.43.0.0/16',
        '172.16.200.0/24',
        '172.16.254.0/24',
        '172.26.0.0/16',
        '172.27.0.0/16',
        '192.168.1.0/24',
    ]
    not_recommended = ['172.16.128.0/24', '172.16.129.0/24']
    if any(ip in IP(i) for i in reserved):
        log.error(f'IP `{i}` 为保留地址')
    elif any(ip in IP(i) for i in not_recommended):
        log.warning(f'IP `{i}` 为不建议地址')
    elif ip not in IP('172.16.0.0/16'):
        log.warning(f'IP `{i}` 不在 DN11 常规段内')
    elif ip in IP('172.16.255.0/24'):
        log.error('服务段请在 `service.yml` 中申请')
    elif len(ip) != 256:
        log.error(f'IP `{i}` 不持有一个 /24 段。对常规段的申请必须是 /24 段')
    else:
        net172_new.add(int(str(ip)[:-3].split('.')[2]))
net172 = set([i for i in range(1, 256) if i not in net172][: len(net172_new)])
if net172_new != net172:
    extra = [f'172.16.{i}.0/24' for i in net172_new - net172]
    want = [f'172.16.{i}.0/24' for i in net172 - net172_new]
    log.warning(f'对于申请的 `{", ".join(extra)}`，建议改为申请 `{", ".join(want)}`')
if 'appendix' in datas[new_file].get('monitor', {}):
    try:
        json.loads('{' + datas[new_file]['monitor']['appendix'] + '}')
    except json.JSONDecodeError:
        log.error('Monitor 附加信息不是合法的 JSON')
if 'custom_node' in datas[new_file].get('monitor', {}):
    try:
        json.loads('{' + datas[new_file]['monitor']['custom_node'] + '}')
    except json.JSONDecodeError:
        log.error('Monitor 附加信息不是合法的 JSON')
log.exit()
