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


if len(sys.argv) > 2:
    log.error("每次 PR 仅支持修改一个文件")
    exit(1)
asn = sys.argv[1][3:-4]

os.chdir('as')
datas = {}
for name in os.listdir():
    if name.endswith('.yml') and name != 'example.yml':
        with open(name, 'r', encoding='utf8') as f:
            data = yaml.load(f, Loader=yaml.Loader)
            datas[name[:-4]] = data
flag = False
for i in ['name', 'ip']:
    if i not in datas[asn]:
        log.error(f'缺少 `{i}` 字段')
        flag = True
if flag:
    log.exit()
existed_ip = {}
existed_domain = {}
for name in datas:
    if name == asn:
        continue
    existed_ip.update({IP(i): name for i in datas[name]['ip']})
    existed_domain.update({i.lower(): name for i in datas[name].get('domain', {}).keys()})
if not all(i.endswith('.dn11') for i in datas[asn].get('domain', {}).keys()):
    log.error("域名必须以 .dn11 结尾")
try:
    [IP(i) for i in datas[asn]['ip']]
except ValueError:
    log.error("IP 格式错误")
for ip in datas[asn]['ip']:
    for eip in existed_ip:
        if IP(ip) in eip:
            log.error(f"IP `{ip}` 已被 `{existed_ip[eip]}` 持有")
        elif eip in IP(ip):
            log.error(f"IP `{ip}` 与 `{existed_ip[eip]}` 持有的 `{eip}` 重叠")
for domain in datas[asn].get('domain', {}):
    if domain.lower() in existed_domain:
        log.error(f"域名 `{domain}` 已被 `{existed_domain[domain.lower()]}` 持有")
    if not datas[asn]['domain'][domain]:
        log.error(f"域名 `{domain}` 未指定 NS")
        continue
    visited = set()
    dup = [x for x in datas[asn]['domain'][domain] if x in visited or (visited.add(x) or False)]
    if dup:
        log.error(f'NS `{", ".join(set(dup))}` 重复定义')
for ns in datas[asn].get('ns', []):
    if not any(ns.endswith(i) for i in datas[asn].get('domain', {})):
        log.error(f'NS 仅可由对应域名的持有者定义，您不持有 `{ns}`')
net172 = [int(str(IP(i))[:-3].split('.')[2]) for i in existed_ip if IP(i) in IP('172.16.0.0/16')]
net172.sort()
net172_new = set()
service = False
for i in datas[asn]['ip']:
    ip = IP(i)
    if ip not in IP('172.16.0.0/16'):
        log.warning(f'IP `{i}` 不在 DN11 常规段内')
    elif ip not in IP('172.16.255.0/24') and len(ip) != 256:
        log.error(f'IP `{i}` 不持有一个 /24 段。对常规段的申请必须是 /24 段')
    elif ip in IP('172.16.255.0/24'):
        service = True
        if len(ip) != 1:
            log.error(f'IP `{i}` 不持有一个 /32 段。对服务段的申请必须是 /32 段')
        if len(datas[asn]['ip']) != 1:
            log.error('服务段每次只能申请一个 IP')
    else:
        net172_new.add(int(str(ip)[:-3].split('.')[2]))
if not service and 'qq' not in datas[asn]:
    log.error('非服务段必须填写 QQ')
net172 = set([i for i in range(1, 256) if i not in net172][: len(net172_new)])
if net172_new != net172:
    extra = [f'172.16.{i}.0/24' for i in net172_new - net172]
    want = [f'172.16.{i}.0/24' for i in net172 - net172_new]
    log.warning(f'对于申请的 `{", ".join(extra)}`，建议改为申请 `{", ".join(want)}`')
if 'appendix' in datas[asn].get('monitor', {}):
    try:
        json.loads('{' + datas[asn]['monitor']['appendix'] + '}')
    except json.JSONDecodeError:
        log.error('Monitor 附加信息不是合法的 JSON')
if 'custom_node' in datas[asn].get('monitor', {}):
    try:
        json.loads('{' + datas[asn]['monitor']['custom_node'] + '}')
    except json.JSONDecodeError:
        log.error('Monitor 附加信息不是合法的 JSON')
log.exit()
