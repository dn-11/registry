#!/usr/bin/env python3
import json
import os
from datetime import datetime
from html import escape

import IPy
import yaml
from py_markdown_table.markdown_table import markdown_table

import iplist


def IP(ip):
    obj = IPy.IP(ip)
    obj.NoPrefixForSingleIp = None
    return obj


datas = {}
with open("as/service.yml", "r", encoding="utf8") as f:
    service = yaml.load(f, Loader=yaml.Loader)
with open("as/dns.yml", "r", encoding="utf8") as f:
    dns = yaml.load(f, Loader=yaml.Loader)
with open("as/ix.yml", "r", encoding="utf8") as f:
    ix = yaml.load(f, Loader=yaml.Loader)
for asn in os.listdir("as"):
    if asn.endswith(".yml") and (asn.startswith("421111") or asn.startswith("422008")):
        with open(f"as/{asn}", "r", encoding="utf8") as f:
            data = yaml.load(f, Loader=yaml.Loader)
            datas[asn[:-4]] = data

normal_ips = []
abnormal_ips = []
net172_existed = set()
monitor_metadata = {
    "announcements": {
        "assigned": [],
        "public": [
            {
                "prefix": "172.16.255.0/24",
                "service": [],
            }
        ],
        "iplist.RESERVED": [str(i) for i in iplist.RESERVED],
    },
    "metadata": {
        "4220084444": {
            "display": "BaiMeow",
            "monitor": {"appendix:": {"str": "str", "str11": ["str1", "str2"]}, "customNode": {}},
        }
    },
}

try:
    os.makedirs("metadata")
except FileExistsError:
    pass

version = int(datetime.now().timestamp())
with open("metadata/version", "w") as f:
    print(version, file=f)

roa = {
    "metadata": {
        "counts": 0,
        "generated": version,
        "valid": 0,
    },
    "roas": [],
}

today = datetime.today().strftime("%Y%m%d")
with open("metadata.old/dn11.zone", "r") as f:
    old_dn11_zone_text = f.read()
old_dn11_zone_serial = next(i for i in old_dn11_zone_text.split("\n") if "SOA" in i)
old_dn11_zone_serial = old_dn11_zone_serial.split()[6]
if old_dn11_zone_serial.startswith(today):
    new_dn11_zone_serial = str(int(old_dn11_zone_serial) + 1)
else:
    new_dn11_zone_serial = today + "01"
with open("metadata/dn11.zone", "w") as f:
    print(
        "$ORIGIN .\n"
        "dn11                    300     IN      SOA     "
        f"root.dn11 hostmaster.dn11 {old_dn11_zone_serial} 60 60 604800 60\n"
        "dn11                    300     IN      NS      172.16.255.53",
        file=f,
    )
with open("metadata.old/dn11-rdns.zone", "r") as f:
    old_rdns_zone_text = f.read()
old_rdns_zone_serial = next(i for i in old_rdns_zone_text.split("\n") if "SOA" in i)
old_rdns_zone_serial = old_rdns_zone_serial.split()[6]
if old_rdns_zone_serial.startswith(today):
    new_rdns_zone_serial = str(int(old_rdns_zone_serial) + 1)
else:
    new_rdns_zone_serial = today + "01"
with open("metadata/dn11-rdns.zone", "w") as f:
    print(
        "$ORIGIN .\n"
        "in-addr.arpa                    300     IN      SOA     "
        f"root.dn11 hostmaster.dn11 {old_rdns_zone_serial} 60 60 604800 60\n"
        "in-addr.arpa                    300     IN      NS      172.16.255.53",
        file=f,
    )
with open("metadata/dn11_roa_bird2.conf", "w") as f:
    for ip in iplist.RESERVED + iplist.PUBLIC:
        if ip == IP("224.0.0.0/4"):
            continue
        print(f"route {str(ip)} max 32 as 4200000000;", file=f)
        roa["roas"].append({"prefix": str(ip), "maxLength": 32, "asn": "AS4200000000"})
        roa["metadata"]["counts"] += 1
        roa["metadata"]["valid"] += len(ip)

for asn, data in datas.items():
    net_172 = [IP(i) for i in data["ip"] if IP(i) in IP("172.16.0.0/16")]
    net_non172 = [IP(i) for i in data["ip"] if IP(i) not in IP("172.16.0.0/16")]
    net_172.sort(key=lambda x: x.int())
    net_non172.sort(key=lambda x: x.int())
    for d in dns:
        if any(IP(d["ip"]) in i for i in net_172 + net_non172):
            d["asn"] = asn
    if len(net_172) > 0:
        normal_ips.append(
            {
                "归属": data["name"],
                "联系方式": data.get("contact", ""),
                "ASN": asn,
                "网段": net_172 + net_non172,
                "备注": data.get("comment", ""),
            }
        )
        net172_existed.update(i for i in range(1, 256) if any(IP(f"172.16.{i}.0/24") in j for j in net_172))
    if len(net_non172) > 0:
        abnormal_ips.append(
            {
                "归属": data["name"],
                "联系方式": data.get("contact", ""),
                "ASN": asn,
                "网段": net_non172 + net_172,
                "备注": data.get("comment", ""),
            }
        )

    monitor_metadata["metadata"][asn] = {"display": data["name"], "monitor": {}}
    if "appendix" in data.get("monitor", {}):
        monitor_metadata["metadata"][asn]["monitor"]["appendix"] = json.loads("{" + data["monitor"]["appendix"] + "}")
    if "custom_node" in data.get("monitor", {}):
        monitor_metadata["metadata"][asn]["monitor"]["customNode"] = json.loads(
            "{" + data["monitor"]["custom_node"] + "}"
        )
    if not monitor_metadata["metadata"][asn]["monitor"]:
        del monitor_metadata["metadata"][asn]["monitor"]
    for ip in data["ip"]:
        roa["roas"].append({"prefix": str(IP(ip)), "maxLength": 32, "asn": f"AS{asn}"})
        roa["metadata"]["counts"] += 1
        roa["metadata"]["valid"] += len(IP(ip))
        with open("metadata/dn11_roa_bird2.conf", "a") as f:
            print(f"route {str(IP(ip))} max 32 as {asn};", file=f)
        monitor_metadata["announcements"]["assigned"].append({"prefix": str(IP(ip)), "asn": asn})
    if "domain" in data or "ns" in data:
        with open("metadata/dn11.zone", "a") as f:
            print(";", file=f)
            if "domain" in data:
                for domain, nss in data["domain"].items():
                    for ns in nss:
                        if domain.endswith(".in-addr.arpa"):
                            with open("metadata/dn11-rdns.zone", "a") as f2:
                                print(f"{domain.ljust(32)}60      IN      NS      {ns}", file=f2)
                        else:
                            print(f"{domain.ljust(24)}60      IN      NS      {ns}", file=f)
            if "ns" in data:
                for server, address in data["ns"].items():
                    print(f"{server.ljust(24)}60      IN      A       {address}", file=f)
with open("metadata/dn11_roa_bird2.conf", "a") as f:
    for s in service:
        asns = [s["asn"]] if type(s["asn"]) is int else s["asn"]
        for asn in asns:
            roa["roas"].append({"prefix": str(IP(s["ip"])), "maxLength": 32, "asn": f"AS{asn}"})
            roa["metadata"]["counts"] += 1
            roa["metadata"]["valid"] += 1
            print(f"route {str(IP(s['ip']))} max 32 as {asn};", file=f)
    for asn in [i["asn"] for i in dns]:
        roa["roas"].append({"prefix": "172.16.255.53/32", "maxLength": 32, "asn": f"AS{asn}"})
        roa["metadata"]["counts"] += 1
        roa["metadata"]["valid"] += 1
        print(f"route 172.16.255.53/32 max 32 as {asn};", file=f)
    for ixrs_ip, ixrs_asn in [(i["rs"]["ip"], i["rs"]["asn"]) for i in ix if "rs" in i]:
        roa["roas"].append({"prefix": str(IP(ixrs_ip)), "maxLength": 32, "asn": f"AS{ixrs_asn}"})
        roa["metadata"]["counts"] += 1
        roa["metadata"]["valid"] += 1
        print(f"route {str(IP(ixrs_ip))} max 32 as {ixrs_asn};", file=f)

roa = {"roas": [{"prefix": i["prefix"], "maxLength": i["maxLength"], "asn": int(i["asn"][2:])} for i in roa["roas"]]}
with open("metadata/dn11_roa_stayrtr.json", "w") as f:
    json.dump(roa, f, ensure_ascii=True, separators=(",", ":"))
with open("metadata/dn11.zone", "r") as f:
    new_dn11_zone_text = f.read()
if new_dn11_zone_text != old_dn11_zone_text:
    new_dn11_zone_text = new_dn11_zone_text.split("\n")
    new_dn11_zone_text[1] = new_dn11_zone_text[1].replace(old_dn11_zone_serial, new_dn11_zone_serial)
    new_dn11_zone_text = "\n".join(new_dn11_zone_text)
    with open("metadata/dn11.zone", "w") as f:
        f.write(new_dn11_zone_text)
with open("metadata/dn11-rdns.zone", "r") as f:
    new_rdns_zone_text = f.read()
if new_rdns_zone_text != old_rdns_zone_text:
    new_rdns_zone_text = new_rdns_zone_text.split("\n")
    new_rdns_zone_text[1] = new_rdns_zone_text[1].replace(old_rdns_zone_serial, new_rdns_zone_serial)
    new_rdns_zone_text = "\n".join(new_rdns_zone_text)
    with open("metadata/dn11-rdns.zone", "w") as f:
        f.write(new_rdns_zone_text)

ipcidr = IPy.IPSet([j for i in normal_ips + abnormal_ips for j in i["网段"]] + [IP("172.16.255.0/24")])
with open("metadata/dn11_ipcidr.txt", "w") as f:
    for i in ipcidr:
        print(i, file=f)

normal_ips = [
    {
        "归属": escape(i["归属"]),
        "ASN": f"`{i['ASN']}`",
        "网段": "<br>".join(f"`{str(j)}`" for j in i["网段"]),
        "备注": "<br>".join(escape(i) for i in f"{i["联系方式"]}\n{str(i["备注"])}".split("\n") if i != ""),
    }
    for i in sorted(normal_ips, key=lambda x: x["网段"][0].int())
]
abnormal_ips = [
    {
        "归属": escape(i["归属"]),
        "ASN": f"`{i['ASN']}`",
        "网段": "<br>".join(f"`{str(j)}`" for j in i["网段"]),
        "备注": "<br>".join(escape(i) for i in f"{i["联系方式"]}\n{str(i["备注"])}".split("\n") if i != ""),
    }
    for i in sorted(abnormal_ips, key=lambda x: x["网段"][0].int())
]
dns_ips = [
    {
        "归属": escape(i["name"]),
        "ASN": f"`{i['asn']}`",
        "Unicast IP": f"`{str(IPy.IP(i['ip']))}`",
    }
    for i in sorted(dns, key=lambda x: int(x["asn"]))
]
ix_ips = [
    {
        "归属": escape(i["name"]),
        "网段": f"`{str(IPy.IP(i['ip']))}`",
        "RS": f"`{i['rs']['asn']}`<br>`{str(IPy.IP(i['rs']['ip']))}`" if "rs" in i else "N/A",
    }
    for i in sorted(ix, key=lambda x: IP(x["ip"]).int())
]
service_ips = []
service.append({"ip": "172.16.255.53", "usage": "DNS", "asn": sorted([i["asn"] for i in dns], key=int)})
for i in sorted(service, key=lambda x: IP(x["ip"]).int()):
    asn = [str(i["asn"])] if type(i["asn"]) is int else [str(j) for j in sorted(i["asn"])]
    monitor_metadata["announcements"]["public"][0]["service"].append(
        {"prefix": str(IP(i["ip"])), "usage": i["usage"], "allowedASN": asn}
    )
    asn_str = "<br>".join(f"`{j}`" for j in asn)
    service_ips.append({"网段": str(IPy.IP(i["ip"])), "ASN": asn_str, "用途": i["usage"]})
with open("metadata/monitor-metadata.json", "w") as f:
    json.dump(monitor_metadata, f, ensure_ascii=True, separators=(",", ":"))
next_net172 = next(i for i in range(1, 256) if i not in net172_existed)
with open("metadata/README.md", "w", encoding="utf-8") as f:
    print(
        "# DN11 信息表\n\n"
        "## 常规段\n\n"
        "DN11 目前整体占据 `172.16.0.0/16`\n\n"
        "新成员请先选择表中无归属的网段，然后再继续向下编排网段。选择网段时尽量与之前的网段连续。\n\n"
        f"*【下一个建议使用的网段为 `172.16.{next_net172}.0/24`】*\n\n"
        "（下表按网段顺序排列）\n",
        file=f,
    )
    if normal_ips:
        md_text = markdown_table(normal_ips).set_params(row_sep="markdown", quote=False).get_markdown()
        md_text = md_text.split("\n", 2)
        print(md_text[0], file=f)
        print("|:-:|:-:|---|---|", file=f)
        print(md_text[2], file=f)
    print(
        "\n"
        "## 使用非标段的成员\n\n"
        "使用非标段的成员如下表。\n\n"
        "新成员不得直接使用自己的非标段，请先在群内讨论。确有需要后再进行申请。\n\n"
        "（下表按网段顺序排列）\n",
        file=f,
    )
    if abnormal_ips:
        md_text = markdown_table(abnormal_ips).set_params(row_sep="markdown", quote=False).get_markdown()
        md_text = md_text.split("\n", 2)
        print(md_text[0], file=f)
        print("|:-:|:-:|---|---|", file=f)
        print(md_text[2], file=f)
    print(
        "\n## 服务段分配表\n\n（下表按网段顺序排列）\n",
        file=f,
    )
    if service_ips:
        md_text = markdown_table(service_ips).set_params(row_sep="markdown", quote=False).get_markdown()
        md_text = md_text.split("\n", 2)
        print(md_text[0], file=f)
        print("|---|:-:|---|", file=f)
        print(md_text[2], file=f)
    if dns_ips:
        print("\n## DNS 服务提供者\n\n（下表按 ASN 顺序排列）\n", file=f)
        md_text = markdown_table(dns_ips).set_params(row_sep="markdown", quote=False).get_markdown()
        md_text = md_text.split("\n", 2)
        print(md_text[0], file=f)
        print("|:-:|:-:|---|", file=f)
        print(md_text[2], file=f)
    if ix_ips:
        print("\n## IX\n\n（下表按网段顺序排列）\n", file=f)
        md_text = markdown_table(ix_ips).set_params(row_sep="markdown", quote=False).get_markdown()
        md_text = md_text.split("\n", 2)
        print(md_text[0], file=f)
        print("|:-:|---|:-:|", file=f)
        print(md_text[2], file=f)

    def ips2str(ips):
        s = ""
        for index, ip in enumerate(str(i) for i in ips):
            s += f"`{ip}`"
            if index != len(ips) - 1:
                if index % 2 == 1:
                    s += "<br>"
                else:
                    s += " "
        return s

    print(
        "\n## 特殊段说明\n\n"
        "| 网段 | 说明 |\n"
        "| --- | --- |\n"
        "| `172.16.0.0/16` | DN11 常规成员段 |\n"
        "| `172.16.255.0/24` | 公共服务段 |\n"
        f"| {ips2str(iplist.RESERVED)} | 保留段  |\n"
        f"| {ips2str(iplist.NOT_RECOMMANDED)} | 不建议 |",
        file=f,
    )
