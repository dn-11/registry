#!/usr/bin/env python3
import json
import os
from datetime import datetime
from html import escape

import IPy
import yaml
from py_markdown_table.markdown_table import markdown_table

dns_root_server = {
    'a': '172.16.7.53',  # GoldenSheep
    'b': '172.16.4.6',  # BaiMeow
    'h': '100.64.0.1',  # Hakuya
    'i': '172.16.2.13',  # Iraze
    'p': '10.18.1.154',  # Potat0
    't': '172.16.3.53',  # TypeScript
}


def IP(ip):
    obj = IPy.IP(ip)
    obj.NoPrefixForSingleIp = None
    return obj


datas = {}
with open('as/service.yml', 'r', encoding='utf8') as f:
    service = yaml.load(f, Loader=yaml.Loader)
service_remain = service.copy()
for asn in os.listdir('as'):
    if asn.endswith('.yml') and (asn.startswith('421111') or asn.startswith('422008')):
        with open(f'as/{asn}', 'r', encoding='utf8') as f:
            data = yaml.load(f, Loader=yaml.Loader)
            datas[asn[:-4]] = data

reserved = [
    IP('10.0.0.0/24'),
    IP('10.42.0.0/16'),
    IP('10.43.0.0/16'),
    IP('172.16.0.0/24'),
    IP('172.16.200.0/24'),
    IP('172.16.254.0/24'),
    IP('172.26.0.0/16'),
    IP('172.27.0.0/16'),
    IP('192.168.1.0/24'),
]
normal_ips = []
abnormal_ips = []

try:
    os.makedirs('metadata-repo')
except FileExistsError:
    pass
try:
    os.makedirs('monitor-metadata')
except FileExistsError:
    pass

roa = {
    "metadata": {
        "counts": 0,
        "generated": int(datetime.now().timestamp()),
        "valid": 0,
    },
    "roas": [],
}

with open('old-metadata/dn11.zone', 'r') as f:
    old_zone_text = f.read()
old_zone_serial = next(i for i in old_zone_text.split('\n') if 'SOA' in i)
old_zone_serial = old_zone_serial.split()[6]
today = datetime.today().strftime('%Y%m%d')
if old_zone_serial.startswith(today):
    new_zone_serial = str(int(old_zone_serial) + 1)
else:
    new_zone_serial = today + '01'
with open('metadata-repo/dn11.zone', 'w') as f:
    print(
        '$ORIGIN .\n'
        'dn11                    300     IN      SOA     '
        f'a.root.dn11 hostmaster.dn11 {old_zone_serial} 60 60 604800 60\n'
        ';',
        file=f,
    )
with open('metadata-repo/dn11_roa_bird2.conf', 'w') as f:
    for ip in reserved + [
        IP('0.0.0.0/5'),
        IP('8.0.0.0/7'),
        IP('11.0.0.0/8'),
        IP('12.0.0.0/6'),
        IP('16.0.0.0/4'),
        IP('32.0.0.0/3'),
        IP('64.0.0.0/3'),
        IP('96.0.0.0/6'),
        IP('100.0.0.0/10'),
        IP('100.128.0.0/9'),
        IP('101.0.0.0/8'),
        IP('102.0.0.0/7'),
        IP('104.0.0.0/5'),
        IP('112.0.0.0/4'),
        IP('128.0.0.0/3'),
        IP('160.0.0.0/5'),
        IP('168.0.0.0/6'),
        IP('172.0.0.0/12'),
        IP('172.32.0.0/11'),
        IP('172.64.0.0/10'),
        IP('172.128.0.0/9'),
        IP('173.0.0.0/8'),
        IP('174.0.0.0/7'),
        IP('176.0.0.0/4'),
        IP('192.0.0.0/9'),
        IP('192.128.0.0/11'),
        IP('192.160.0.0/13'),
        IP('192.169.0.0/16'),
        IP('192.170.0.0/15'),
        IP('192.172.0.0/14'),
        IP('192.176.0.0/12'),
        IP('192.192.0.0/10'),
        IP('193.0.0.0/8'),
        IP('194.0.0.0/7'),
        IP('196.0.0.0/6'),
        IP('200.0.0.0/5'),
        IP('208.0.0.0/4'),
        IP('224.0.0.0/3'),
    ]:
        print(f'route {str(ip)} max 32 as 4200000000;', file=f)
        roa['roas'].append({'prefix': str(ip), 'maxLength': 32, 'asn': 'AS4200000000'})
        roa['metadata']['counts'] += 1
        roa['metadata']['valid'] += len(ip)

for asn, data in datas.items():
    net_172 = [IP(i) for i in data['ip'] if IP(i) in IP('172.16.0.0/16')]
    net_non172 = [IP(i) for i in data['ip'] if IP(i) not in IP('172.16.0.0/16')]
    net_172.sort(key=lambda x: x.int())
    net_non172.sort(key=lambda x: x.int())
    if len(net_172) > 0:
        normal_ips.append(
            {
                '归属': data['name'],
                '联系方式': data.get('contact', ''),
                'ASN': asn,
                '网段': net_172 + net_non172,
                '备注': data.get('comment', ''),
            }
        )
    if len(net_non172) > 0:
        abnormal_ips.append(
            {
                '归属': data['name'],
                '联系方式': data.get('contact', ''),
                'ASN': asn,
                '网段': net_non172 + net_172,
                '备注': data.get('comment', ''),
            }
        )

    for i in service_remain:
        if str(i.get('asn', '')) == asn:
            data['ip'].append(i['ip'])
            service_remain.remove(i)
    temp = {'display': data['name'], 'announce': [str(IP(i)) for i in data['ip']]}
    if 'appendix' in data.get('monitor', {}):
        temp['appendix'] = json.loads('{' + data['monitor']['appendix'] + '}')
    if 'custom_node' in data.get('monitor', {}):
        temp['customNode'] = json.loads('{' + data['monitor']['custom_node'] + '}')
    with open(f'monitor-metadata/{asn}.json', 'w') as f:
        json.dump(temp, f, ensure_ascii=False, indent=4)
    for ip in data['ip']:
        roa['roas'].append({'prefix': str(IP(ip)), 'maxLength': 32, 'asn': f'AS{asn}'})
        roa['metadata']['counts'] += 1
        roa['metadata']['valid'] += len(IP(ip))
        with open('metadata-repo/dn11_roa_bird2.conf', 'a') as f:
            print(f'route {str(IP(ip))} max 32 as {asn};', file=f)
    with open('metadata-repo/dn11.zone', 'a') as f:
        if 'domain' in data:
            for domain, nss in data['domain'].items():
                for ns in nss:
                    print(f'{domain.ljust(24)}60      IN      NS      {ns}', file=f)
        if 'ns' in data:
            for server, address in data['ns'].items():
                print(f'{server.ljust(24)}60      IN      A       {address}', file=f)
        if 'domain' in data or 'ns' in data:
            print(';', file=f)
with open('metadata-repo/dn11_roa_bird2.conf', 'a') as f:
    for s in (i for i in service_remain if 'asn' in i):
        roa['roas'].append({'prefix': str(IP(s["ip"])), 'maxLength': 32, 'asn': f'AS{s["asn"]}'})
        roa['metadata']['counts'] += 1
        roa['metadata']['valid'] += len(IP(s["ip"]))
        print(f'route {str(IP(s["ip"]))} max 32 as {s["asn"]};', file=f)
with open('metadata-repo/dn11_roa_gortr.json', 'w') as f:
    json.dump(roa, f, ensure_ascii=True, separators=(',', ':'))
with open('metadata-repo/dn11.zone', 'a') as f:
    for server in dns_root_server.keys():
        print(f'dn11                    60      IN      NS      {server}.root.dn11', file=f)
    print(';', file=f)
    for server, address in dns_root_server.items():
        print(f'{server}.root.dn11 {" " * (13 - len(server))}60      IN      A       {address}', file=f)
with open('metadata-repo/dn11.zone', 'r') as f:
    new_zone_text = f.read()
if new_zone_text != old_zone_text:
    new_zone_text = new_zone_text.split('\n')
    new_zone_text[1] = new_zone_text[1].replace(old_zone_serial, new_zone_serial)
    new_zone_text = '\n'.join(new_zone_text)
    with open('metadata-repo/dn11.zone', 'w') as f:
        f.write(new_zone_text)

normal_ips = [
    {
        '归属': escape(i['归属']),
        'ASN': f"`{i['ASN']}`",
        '网段': '<br>'.join(f'`{str(j)}`' for j in i['网段']),
        '备注': '<br>'.join(escape(i) for i in str(i['联系方式']).split('\n') + str(i['备注']).split('\n')),
    }
    for i in sorted(normal_ips, key=lambda x: x['网段'][0].int())
]
abnormal_ips = [
    {
        '归属': escape(i['归属']),
        'ASN': f"`{i['ASN']}`",
        '网段': '<br>'.join(f'`{str(j)}`' for j in i['网段']),
        '备注': '<br>'.join(escape(i) for i in str(i['联系方式']).split('\n') + str(i['备注']).split('\n')),
    }
    for i in sorted(abnormal_ips, key=lambda x: x['网段'][0].int())
]
service_ips = [
    {
        '网段': str(IPy.IP(i['ip'])),
        'ASN': f"`{i.get('asn', 'Anycast')}`",
        '用途': i.get('usage', ''),
    }
    for i in sorted(service, key=lambda x: IP(x['ip']).int())
]
with open('metadata-repo/README.md', 'w', encoding='utf-8') as f:
    print(
        '# DN11 信息表\n\n'
        '## 常规段\n\n'
        'DN11 目前整体占据 `172.16.0.0/16`\n\n'
        '新成员请先选择表中无归属的网段，然后再继续向下编排网段。选择网段时尽量与之前的网段连续。\n\n'
        '（下表按网段顺序排列）\n',
        file=f,
    )
    if normal_ips:
        md_text = markdown_table(normal_ips).set_params(row_sep='markdown', quote=False).get_markdown()
        md_text = md_text.split('\n', 2)
        print(md_text[0], file=f)
        print('|:-:|:-:|---|---|', file=f)
        print(md_text[2], file=f)
    print(
        '\n' '## 使用非标段的成员\n\n' '使用非标段的成员如下表。\n\n' '新成员不得直接使用自己的非标段，请先在群内讨论。确有需要后再进行申请。\n\n' '（下表按网段顺序排列）\n',
        file=f,
    )
    if abnormal_ips:
        md_text = markdown_table(abnormal_ips).set_params(row_sep='markdown', quote=False).get_markdown()
        md_text = md_text.split('\n', 2)
        print(md_text[0], file=f)
        print('|:-:|:-:|---|---|', file=f)
        print(md_text[2], file=f)
    print(
        '\n## 服务段分配表\n\n（下表按网段顺序排列）\n',
        file=f,
    )
    if service_ips:
        md_text = markdown_table(service_ips).set_params(row_sep='markdown', quote=False).get_markdown()
        md_text = md_text.split('\n', 2)
        print(md_text[0], file=f)
        print('|---|:-:|---|', file=f)
        print(md_text[2], file=f)
    reserved_str = ''
    for index, ip in enumerate(str(i) for i in reserved):
        reserved_str += f'`{ip}`'
        if index % 2 == 1:
            reserved_str += '<br>'
        else:
            reserved_str += ' '
    print(
        '\n## 特殊段说明\n\n'
        '| 网段 | 说明 |\n'
        '| --- | --- |\n'
        '| `172.16.0.0/16` | DN11 常规成员段 |\n'
        '| `172.16.255.0/24` | 公共服务段 |\n'
        f'| {reserved_str.strip()} | 保留段  |\n'
        '| `172.16.128.0/24`<br>`172.16.129.0/24` | 不建议 |\n',
        file=f,
    )
