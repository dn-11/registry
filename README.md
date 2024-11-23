# DN11 Registry

## What

这是 DN11 的成员注册表。所有 DN11 的资源均需在此处注册，包括但不限于：

- ASN
- IP 段
- 域名

## Why

为了保证 DN11 的资源的可用性，我们需要对资源进行统一管理。

通过在此处注册成员信息，我们的 Checker 可以自动规避 IP 段冲突、空缺，域名冲突等问题。

同时，Generator 会自动生成各类标准文件，如：

- Monitor ([主站](https://status.dn11.top/) / [备站](https://monitor.dn11.baimeow.cn/))
- 信息表 ([GitHub](https://github.com/dn-11/metadata/blob/main/README.md))
- ROA
  - Bird2 风格 ([GitHub](https://raw.githubusercontent.com/dn-11/metadata/main/dn11_roa_bird2.conf) / [Tencent COS](https://metadata.dn11.baimeow.cn/dn11_roa_bird2.conf))
  - GoRTR 风格 ([GitHub](https://raw.githubusercontent.com/dn-11/metadata/main/dn11_roa_gortr.json) / [Tencent COS](https://metadata.dn11.baimeow.cn/dn11_roa_gortr.json))
- Zone 文件
  - DN11 Zone ([GitHub](https://raw.githubusercontent.com/dn-11/metadata/main/dn11.zone) / [Tencent COS](https://metadata.dn11.baimeow.cn/dn11.zone))
  - rDNS Zone ([GitHub](https://raw.githubusercontent.com/dn-11/metadata/main/dn11-rdns.zone) / [Tencent COS](https://metadata.dn11.baimeow.cn/dn11-rdns.zone))
- IP-Cidr 文件 ([GitHub](https://raw.githubusercontent.com/dn-11/metadata/main/dn11_ipcidr.txt) / [Tencent COS](https://metadata.dn11.baimeow.cn/dn11_ipcidr.txt))

## How

### 成员注册

您仅需要在 `as` 目录中创建一个 YAML 文件，文件名为 `<your-asn>.yml`，然后以 [`example.yml`](https://github.com/dn-11/registry/blob/main/as/example.yml) 为模板填写。填写完成后提交一个 PR，根据 Checker 回复修改您的配置，然后等待管理员合并即可。

- `ASN`

  **必填**（文件名）

  格式为 `421111xxxx` 或 `422008xxxx` (仅 Vidar 成员)

  后四位任选，无冲突即可。

- `name`

  **必填**

  您的名字 / ID

- `contact`

  **必填** (为非个人注册时除外)

  联系方式，如 QQ / Email

  如使用 QQ 号等纯数字，请使用引号包裹，确保该项的值为字符串。

- `ip`

  **必填**，可多个

  您所使用的 IP 段

  DN11 默认从 `172.16.0.0/16` 段中使用 `/24` 作为成员段。请优先选择该段内的最小一个未使用的 `/24` 地址。

  您可在 [信息表](https://github.com/dn-11/metadata/blob/main/README.md) 中查看已使用的 IP 段和下一个建议使用的网段。

  如您确需使用其他 IP，请在群中说明情况。

- `domain`

  **选填**

  可在此处注册您的域名，以便我们为您生成 Zone 文件。

  如注册域名，则每个域名至少提供一个 NS 记录的 IP 地址。

  此处也可用于注册 rDNS 域名，格式与普通域名相同。请注意，目前仅子网掩码为 `/8`、`/16`、`/24` 的 IP 地址可注册 rDNS 域名。

- `ns`

  **选填**

  可在此处注册您的 NS 记录，以便我们为您生成 Zone 文件。

  每个 NS 记录对应一个 IP 地址。

  请注意，注册域名是不一定需要注册 NS 记录。如您使用其他成员提供的 NS 服务器，则无需注册 NS 记录。

- `comment`

  **选填**

  备注信息。会在信息表等场合展示。

- `monitor`

  **选填**。但若有，则至少包含下面任一项

  Monitor 额外配置项

  - `appendix`

    附加信息，会在 Monitor 中展示

  - `custom`

    自定义 ECharts 效果。参考 [此处](https://echarts.apache.org/zh/option.html#series-graph.data)

    JSON 格式

### 服务段注册

DN11 将 `172.16.255.0/24` 作为服务段，用于提供各类服务，每个服务持有一个 IP 地址。

如需注册新服务，可修改 [`as/services.yml`](https://github.com/dn-11/registry/blob/main/as/service.yml) 文件。

DNS 服务使用 `172.16.255.53`，无需在此处注册。如需加入 Anycast，请参见下一章节。

- `ip`

  **必填**

  服务 IP 地址，必须为单个 IP 地址

- `usage`

  **必填**

  服务用途。

- `asn`

  **必填**

  提供服务的 ASN。如 AnyCast 可用列表填写多个 ASN。

### Anycast DNS 注册

`172.16.255.53` 为 DN11 的 Anycast DNS。希望提供 Anycast 的成员需要修改 [`as/dns.yml`](https://github.com/dn-11/registry/blob/main/as/dns.yml) 文件。

- `name`

  **必填**

  您的名字 / ID

- `ip`

  **必填**

  Anycast DNS 服务的 Unicast IP 地址

### IX 注册

DN11 中有数个 IX 接入点。为避免 IX 内使用的网段被其他成员误注册，新部署 IX 接入点后需要修改 [`as/ix.yml`](https://github.com/dn-11/registry/blob/main/as/ix.yml) 文件以注册。

- `name`

  **必填**

  IX 接入点名称

- `ip`

  **必填**

  IX 接入点 IP 段

- `rs`

  **选填**。但若有，则必须包含下面两项

  IX RS 服务器配置

  - `asn`

    IX RS 服务器 ASN

  - `ip`

    IX RS 服务器 IP 地址
