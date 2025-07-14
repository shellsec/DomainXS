# DomainXS - 域名信息查询工具

DomainXS是一个功能强大的域名信息查询工具，可以帮助您快速获取域名的各种信息，包括WHOIS信息、SSL证书状态、IP地址及归属地等。

## 功能特点

- **WHOIS信息查询**：获取域名的注册人、注册机构、注册时间、过期时间等信息
- **注册年限计算**：自动计算域名已注册的年数
- **SSL证书检查**：验证域名SSL证书的有效性、颁发者、有效期等信息
- **IP地址解析**：获取域名对应的IP地址
- **IP归属地查询**：查询IP地址的地理位置、ISP和组织信息
- **批量查询**：支持从文件中批量读取域名进行查询
- **结果导出**：将查询结果保存到文件中

## 安装

### 依赖项

- Python 3.6+
- 以下Python库：
  - python-whois
  - requests
  - cryptography
  - socket
  - ssl
  - datetime
  - json
  - re
  - subprocess
  - time
  - os
  - sys

### 安装步骤

1. 克隆仓库：
   ```
   git clone https://github.com/shellsec/DomainXS.git
   cd DomainXS
   ```

2. 安装依赖：
   ```
   pip install -r requirements.txt
   ```

## 使用方法

### 单个域名查询

```
python domain_info.py -d example.com
```

### 批量查询

1. 创建一个包含域名列表的文本文件，每行一个域名
2. 运行以下命令：
   ```
   python domain_info.py -f domains.txt
   ```

### 查询结果

查询结果将显示在控制台，并保存到以下文件：
- `results.txt`：包含所有查询结果
- `company_list.txt`：提取的公司/组织名称列表

## 输出示例

```
域名: example.com
注册人: 未找到注册人信息
组织/公司: 示例组织
注册时间: 1995-08-14
注册年限: 29年
过期时间: 2025-08-13
SSL证书: 状态: 有效, 颁发者: DigiCert TLS RSA SHA256 2020 CA1, 有效期: 2023-03-07 至 2024-03-06, 剩余天数: 120, 加密算法: TLS_AES_256_GCM_SHA384
IP归属地信息:
IP: 93.184.216.34, 国家: 美国, 地区: 弗吉尼亚, 城市: 阿什本, ISP: Cloudflare, Inc., 组织: Cloudflare, Inc.
```

## 注意事项

- WHOIS查询可能受到服务提供商的速率限制
- IP归属地信息的准确性取决于第三方数据库
- 某些域名可能无法获取完整的WHOIS信息

## 许可证

[MIT License](LICENSE)