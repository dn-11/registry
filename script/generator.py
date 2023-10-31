#!/usr/bin/env python3
import json
import os
from datetime import datetime
from html import escape

import requests
import yaml
from IPy import IP
from py_markdown_table.markdown_table import markdown_table

datas = {}
for asn in os.listdir('as'):
    if asn.endswith('.yml') and asn != 'example.yml':
        with open(f'as/{asn}', 'r', encoding='utf8') as f:
            data = yaml.load(f, Loader=yaml.Loader)
            datas[asn[:-4]] = data

normal_ips = []
abnormal_ips = []
service_ips = []

try:
    os.makedirs('monitor-metadata')
except FileExistsError:
    pass

old_zone_serial = requests.get('https://raw.githubusercontent.com/hdu-dn11/metadata/main/dn11.zone').text
old_zone_serial = next(i for i in old_zone_serial.split('\n') if 'SOA' in i)
old_zone_serial = old_zone_serial.split()[6]
today = datetime.today().strftime('%Y%m%d')
if old_zone_serial.startswith(today):
    new_zone_serial = str(int(old_zone_serial) + 1)
else:
    new_zone_serial = today + '01'
with open('dn11.zone', 'w') as f:
    print(
        '$ORIGIN .\n'
        'dn11                    300     IN      SOA     '
        f'a.root.dn11 hostmaster.dn11 {new_zone_serial} 60 60 604800 60\n'
        ';',
        file=f,
    )

for asn, data in datas.items():
    net_172 = [IP(i) for i in data['ip'] if IP(i) in IP('172.16.0.0/16')]
    net_non172 = [IP(i) for i in data['ip'] if IP(i) not in IP('172.16.0.0/16')]
    net_172.sort(key=lambda x: x.int())
    net_non172.sort(key=lambda x: x.int())
    if len(net_172) == 1 and len(net_non172) == 0 and net_172[0] in IP('172.16.255.0/24'):
        service_ips.append(
            {
                '网段': net_172[0],
                'ASN': asn if asn.startswith('421111') or asn.startswith('422008') else 'Anycast',
                '用途': data.get('comment', ''),
            }
        )
    elif len(net_172) > 0:
        normal_ips.append(
            {
                '归属': data['name'],
                'QQ': data['qq'],
                'ASN': asn,
                '网段': net_172 + net_non172,
                '备注': data.get('comment', ''),
            }
        )
    else:
        abnormal_ips.append(
            {
                '归属': data['name'],
                'QQ': data['qq'],
                'ASN': asn,
                '网段': net_non172,
                '备注': data.get('comment', ''),
            }
        )

    if not (asn.startswith('421111') or asn.startswith('422008')):
        continue

    temp = {'display': data['name'], 'announce': [str(IP(i)) for i in data['ip']]}
    if 'appendix' in data.get('monitor', {}):
        temp['appendix'] = json.loads('{' + data['monitor']['appendix'] + '}')
    if 'custom_node' in data.get('monitor', {}):
        temp['custom_node'] = json.loads('{' + data['monitor']['custom_node'] + '}')
    with open(f'monitor-metadata/{asn}.json', 'w') as f:
        json.dump(temp, f, ensure_ascii=False, indent=4)
    for ip in data['ip']:
        with open('dn11_roa_bird2.conf', 'a') as f:
            print(f'route {str(IP(ip))} max 32 as {asn};', file=f)
    with open('dn11.zone', 'a') as f:
        flag = False
        if 'domain' in data:
            flag = True
            for domain, nss in data['domain'].items():
                for ns in nss:
                    print(f'{domain.ljust(24)}60      IN      NS      {ns}', file=f)
        if 'ns' in data:
            flag = True
            for server, address in data['ns'].items():
                print(f'{server.ljust(24)}60      IN      A       {address}', file=f)
        if flag:
            print(';', file=f)
with open('dn11.zone', 'a') as f:
    print(
        'dn11                    60      IN      NS      a.root.dn11\n'
        'dn11                    60      IN      NS      i.root.dn11\n'
        'dn11                    60      IN      NS      t.root.dn11\n'
        ';\n'
        'a.root.dn11             60      IN      A       172.16.7.53\n'
        'i.root.dn11             60      IN      A       172.16.2.13\n'
        't.root.dn11             60      IN      A       172.16.3.53',
        file=f,
    )

normal_ips = [
    {
        '归属': escape(i['归属']) + f'<br>{i["QQ"]}',
        'ASN': f"`{i['ASN']}`",
        '网段': '<br>'.join(f'`{str(j)}`' for j in i['网段']),
        '备注': i['备注'],
    }
    for i in sorted(normal_ips, key=lambda x: x['网段'][0].int())
]
abnormal_ips = [
    {
        '归属': escape(i['归属']) + f'<br>{i["QQ"]}',
        'ASN': f"`{i['ASN']}`",
        '网段': '<br>'.join(f'`{str(j)}`' for j in i['网段']),
        '备注': i['备注'],
    }
    for i in sorted(abnormal_ips, key=lambda x: x['网段'][0].int())
]
service_ips = [
    {
        '网段': str(i['网段']),
        'ASN': f"`{i['ASN']}`",
        '用途': i['用途'],
    }
    for i in sorted(service_ips, key=lambda x: x['网段'].int())
]
with open('README.md', 'w', encoding='utf-8') as f:
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
        '\n' '## 使用非标段的成员\n\n' '使用非标段的成员如下表。\n\n' '新成员不得直接使用自己的非标段，请先在群内讨论。确有需要后再在此处填写相关信息。\n\n' '（下表按网段顺序排列）\n',
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
    print(
        '\n## 特殊段说明\n\n'
        '| 网段 | 说明 |\n'
        '| --- | --- |\n'
        '| `172.16.0.0/16` | DN11 常规成员段 |\n'
        '| `172.16.255.0/24` | 公共服务段 |\n'
        '| `10.0.0.0/24` `10.42.0.0/16`<br>`10.43.0.0/16` `172.16.200.0/24`<br>`172.16.254.0/24` `172.26.0.0/16`<br>`172.27.0.0/16` `192.168.1.1/24` | 保留段  |\n'
        '| `172.16.128.0/24`<br>`172.16.129.0/24` | 不建议 |\n',
        file=f,
    )
