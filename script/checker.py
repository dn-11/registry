#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

import yaml
from IPy import IP
from netaddr import IPSet


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

    def try_exit(self):
        if self.has_error:
            print()
            print('请修复错误后再提交')
            print()
            print('注意：由于格式错误等原因，配置文件未被完整校验。请修复后重新查看校验结果。')
            exit(1)


log = log()

if len(sys.argv) == 1:
    print('无修改的文件')
    exit(0)
elif len(sys.argv) > 2:
    log.error("每次 PR 仅支持修改一个文件")
for arg in sys.argv[1:]:
    path = Path(arg)
    if str(path.parent) != 'as':
        log.error(f"修改了非 as 目录文件: `{arg}`")
    elif path.suffix != '.yml':
        log.error(f"文件 `{arg}` 非 yml 格式")
    elif path.stem == 'example':
        log.warning("修改了 `example.yml` 文件")
    elif path.stem == 'service':
        continue
    else:
        try:
            asn = int(path.stem)
            if not (4211110000 <= asn <= 4211119999 or 4220080000 <= asn <= 4220089999):
                raise ValueError
        except ValueError:
            log.error(f"文件 `{arg}` ASN 格式错误，必须为 `421111xxxx` 或 `422008xxxx` (Vidar 成员)")
log.try_exit()

os.chdir('as')
new_file = Path(sys.argv[1]).stem

if new_file == 'service':
    with open('service.yml', 'r', encoding='utf8') as f:
        data = yaml.load(f, Loader=yaml.Loader)
    if len(set(i['ip'] for i in data)) != len(data):
        log.error('服务段有重复 IP')
    for i in data:
        ip = IP(i['ip'])
        ip.NoPrefixForSingleIp = None
        if len(ip) != 1:
            log.error(f'IP `{str(ip)}` 不为单 IP。对服务段的申请必须是 /32')
        elif ip not in IP('172.16.255.0/24'):
            log.error(f'IP `{str(ip)}` 不在服务段 `172.16.255.0/24` 内')
    log.exit()

datas = {}
for asn in os.listdir():
    if asn.endswith('.yml') and (asn.startswith('421111') or asn.startswith('422008')):
        with open(asn, 'r', encoding='utf8') as f:
            data = yaml.load(f, Loader=yaml.Loader)
            datas[asn[:-4]] = data
if 'ip' not in datas[new_file]:
    log.error('缺少 `ip` 字段')
elif type(datas[new_file]['ip']) is not list:
    log.error('`ip` 字段必须为列表')
elif len(IPSet(datas[new_file]['ip']).iter_cidrs()) != len(datas[new_file]['ip']):
    log.error('所申请 IP 有重叠')
if 'name' not in datas[new_file]:
    log.error('缺少 `name` 字段')
elif type(datas[new_file]['name']) is not str:
    log.error('`name` 字段必须为字符串')
if 'domain' in datas[new_file]:
    if type(datas[new_file]['domain']) is not dict:
        log.error('`domain` 字段必须为字典')
    else:
        for domain, ns_server in datas[new_file]['domain'].items():
            if type(ns_server) is not list:
                log.error(f'域名 `{domain}` 的 NS 服务器设置不为列表')
if 'ns' in datas[new_file]:
    if type(datas[new_file]['ns']) is not dict:
        log.error('`ns` 字段必须为字典')
    else:
        for ns_server, ip in datas[new_file]['ns'].items():
            if type(ip) is not str:
                log.error(f'NS `{ns_server}` 的 IP 不为字符串')
if 'contact' not in datas[new_file]:
    log.warning('缺少联系方式')
elif type(datas[new_file]['contact']) is not str:
    log.error('`contact` 字段必须为字符串')
if 'comment' in datas[new_file] and type(datas[new_file]['comment']) is not str:
    log.error('`comment` 字段必须为字符串')
if 'monitor' in datas[new_file]:
    if type(datas[new_file]['monitor']) is not dict:
        log.error('`monitor` 字段必须为字典')
    elif any(i in datas[new_file]['monitor'] for i in ['appendix', 'custom_node']):
        if 'appendix' in datas[new_file] and type(datas[new_file]['monitor']['appendix']) is not str:
            log.error('`monitor` 的 `appendix` 字段必须为字符串')
        if 'custom_node' in datas[new_file] and type(datas[new_file]['monitor']['custom_node']) is not str:
            log.error('`monitor` 的 `custom_node` 字段必须为字符串')
    else:
        log.error('`monitor` 字段必须至少包含 `appendix` 或 `custom_node`')
log.try_exit()

existed_ip = {}
existed_domain = {}
existed_ns = {}
for asn in datas:
    if asn == new_file:
        continue
    existed_ip.update({IP(i): asn for i in datas[asn]['ip']})
    existed_domain.update({i.lower(): asn for i in datas[asn].get('domain', {}).keys()})
    existed_ns.update({i.lower(): asn for i in datas[asn].get('ns', {}).keys()})
if not all(i.endswith('.dn11') for i in datas[new_file].get('domain', {}).keys()):
    log.error("域名必须以 .dn11 结尾")
for i in datas[new_file]['ip']:
    try:
        IP(i)
    except ValueError:
        log.error(f"IP `{i}` 格式错误")
for i in datas[new_file].get('ns', {}).values():
    try:
        IP(i)
    except ValueError:
        log.error(f"NS IP `{i}` 格式错误")
log.try_exit()
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
for ns in datas[new_file].get('ns', {}).keys():
    if not any(ns.endswith(i) for i in datas[new_file].get('domain', {})):
        log.error(f'NS 仅可由对应域名的持有者定义，您不持有 `{ns}`')
    else:
        existed_ns[ns.lower()] = new_file
for ns in datas[new_file].get('domain', {}).values():
    for i in ns:
        if i.lower() not in existed_ns:
            log.error(f'NS `{i}` 未被定义')
net172 = [int(str(IP(i))[:-3].split('.')[2]) for i in existed_ip if IP(i) in IP('172.16.0.0/16')]
net172.sort()
net172_new = set()
for i in datas[new_file]['ip']:
    ip = IP(i)
    reserved = [
        '10.0.0.0/24',
        '10.42.0.0/16',
        '10.43.0.0/16',
        '172.16.0.0/24',
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
