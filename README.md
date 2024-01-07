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
- 信息表 ([GitHub](https://github.com/hdu-dn11/metadata/blob/main/README.md))
- ROA
  - Bird2 风格 ([GitHub](https://raw.githubusercontent.com/hdu-dn11/metadata/main/dn11_roa_bird2.conf) / [Tencent COS](https://metadata.dn11.baimeow.cn/dn11_roa_bird2.conf))
  - GoRTR 风格 ([GitHub](https://raw.githubusercontent.com/hdu-dn11/metadata/main/dn11_roa_gortr.json) / [Tencent COS](https://metadata.dn11.baimeow.cn/dn11_roa_gortr.json))
- Zone 文件 ([GitHub](https://raw.githubusercontent.com/hdu-dn11/metadata/main/dn11.zone) / [Tencent COS](https://metadata.dn11.baimeow.cn/dn11.zone))

## How

### 成员注册

您仅需要在 `as` 目录中创建一个 YAML 文件，文件名为 `<your-asn>.yml`，然后以 [`example.yml`](https://github.com/hdu-dn11/registry/blob/main/as/example.yml) 为模板填写。填写完成后提交一个 PR，根据 Checker 回复修改您的配置，然后等待管理员合并即可。

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

  您可在 [信息表](https://github.com/hdu-dn11/metadata/blob/main/README.md) 中查看已使用的 IP 段和下一个建议使用的网段。

  如您确需使用其他 IP，请在群中说明情况。

- `domain`

  **选填**

  可在此处注册您的域名，以便我们为您生成 Zone 文件。

  如注册域名，则每个域名至少提供一个 NS 记录的 IP 地址。

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

如需注册新服务，可修改 [`as/services.yml`](https://github.com/hdu-dn11/registry/blob/main/as/service.yml) 文件。

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

`172.16.255.53` 为 DN11 的 Anycast DNS。希望提供 Anycast 的成员需要修改 [`as/dns.yml`](https://github.com/hdu-dn11/registry/blob/main/as/dns.yml) 文件。

- `name`

  **必填**

  您的名字 / ID

- `ip`

  **必填**

  Anycast DNS 服务的单播 IP 地址

- `root_domain`

  **必填**

  根域名前缀

  DN11 DNS 根域名为 `<prefix>.root.dn11`
