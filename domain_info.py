import requests
import whois
import ssl
import socket
from datetime import datetime
import time
import random
import threading
import subprocess
from functools import wraps

requests.packages.urllib3.disable_warnings()

# 添加超时装饰器
def timeout(seconds=30, error_message="操作超时"):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = [None]
            error = [None]
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    error[0] = e
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(seconds)
            
            if thread.is_alive():
                raise TimeoutError(error_message)
            if error[0]:
                raise error[0]
            return result[0]
        return wrapper
    return decorator

# 使用系统whois命令获取域名信息
def get_whois_from_command(domain):
    try:
        # 检查系统是否安装了whois命令
        try:
            # 在Windows上，先检查whois命令是否存在
            if subprocess.run(['where', 'whois'], capture_output=True, text=True).returncode != 0:
                print("系统未安装whois命令")
                return None
        except Exception as e:
            # 如果where命令失败，可能是非Windows系统或其他问题
            print(f"检查whois命令是否存在时出错: {str(e)}")
            # 直接尝试执行whois命令
            pass
            
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=20)
        return result.stdout
    except FileNotFoundError:
        print("系统未安装whois命令")
        return None
    except subprocess.SubprocessError as e:
        print(f"系统whois命令执行失败: {str(e)}")
        return None
    except Exception as e:
        print(f"执行whois命令时出错: {str(e)}")
        return None

def get_domain_info(domain):
    """获取域名的WHOIS信息，包括注册人、组织和注册时间"""
    try:
        print(f"开始WHOIS查询: {domain}")
        
        # 首先尝试使用系统whois命令
        print("尝试使用系统whois命令...")
        whois_text = get_whois_from_command(domain)
        if whois_text:
            print("成功获取系统whois命令输出，正在解析...")
            info = {
                'registrant': "未找到注册人信息",
                'organization': "未找到组织信息",
                'creation_date': "未找到注册时间",
                'expiration_date': "未找到过期时间"
            }
            
            # 解析系统whois命令输出
            for line in whois_text.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # 尝试提取注册人信息
                if "Registrant Name" in line or "registrant:" in line:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        info['registrant'] = parts[1].strip()
                
                # 尝试提取组织信息
                if "Registrant Organization" in line or "org:" in line or "Organization" in line:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        info['organization'] = parts[1].strip()
                
                # 尝试提取注册时间
                if "Created" in line or "Creation Date" in line or "created" in line:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        info['creation_date'] = parts[1].strip()
                
                # 尝试提取过期时间
                if "Expiry" in line or "Expiration" in line or "expires" in line:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        info['expiration_date'] = parts[1].strip()
            
            # 如果系统whois命令获取到了信息，直接返回
            if info['creation_date'] != "未找到注册时间" or info['organization'] != "未找到组织信息":
                return info
        
        # 如果系统whois命令失败或未获取到足够信息，尝试使用python-whois库
        print("尝试使用python-whois库...")
        # 设置超时时间
        socket.setdefaulttimeout(15)
        
        # 使用线程和超时来执行whois查询
        result = [None]
        error = [None]
        
        def whois_thread():
            try:
                result[0] = whois.whois(domain)
            except Exception as e:
                error[0] = e
        
        thread = threading.Thread(target=whois_thread)
        thread.daemon = True
        thread.start()
        thread.join(15)  # 等待15秒
        
        if thread.is_alive():
            print("python-whois库查询超时")
            return {
                'registrant': "WHOIS查询超时",
                'organization': "WHOIS查询超时",
                'creation_date': "WHOIS查询超时",
                'expiration_date': "WHOIS查询超时"
            }
        
        if error[0]:
            raise error[0]
        
        w = result[0]
        if w:
            print(f"WHOIS查询成功，正在解析数据...")
            
            # 打印原始WHOIS数据以便调试
            print(f"原始WHOIS数据: {w}")
            
            info = {}
            
            # 获取注册人
            if hasattr(w, 'registrant_name') and w.registrant_name:
                info['registrant'] = w.registrant_name
            elif hasattr(w, 'name') and w.name:
                info['registrant'] = w.name
            else:
                info['registrant'] = "未找到注册人信息"
                
            # 获取组织/公司
            if hasattr(w, 'org') and w.org:
                info['organization'] = w.org
            elif hasattr(w, 'registrant_org') and w.registrant_org:
                info['organization'] = w.registrant_org
            elif hasattr(w, 'organization') and w.organization:
                info['organization'] = w.organization
            else:
                info['organization'] = "未找到组织信息"
                
            # 获取注册时间
            if hasattr(w, 'creation_date') and w.creation_date:
                try:
                    if isinstance(w.creation_date, list):
                        info['creation_date'] = w.creation_date[0].strftime("%Y-%m-%d")
                    else:
                        info['creation_date'] = w.creation_date.strftime("%Y-%m-%d")
                except Exception as e:
                    print(f"格式化注册时间时出错: {str(e)}")
                    info['creation_date'] = f"格式错误: {str(w.creation_date)}"
            else:
                info['creation_date'] = "未找到注册时间"
                
            # 获取过期时间
            if hasattr(w, 'expiration_date') and w.expiration_date:
                try:
                    if isinstance(w.expiration_date, list):
                        info['expiration_date'] = w.expiration_date[0].strftime("%Y-%m-%d")
                    else:
                        info['expiration_date'] = w.expiration_date.strftime("%Y-%m-%d")
                except Exception as e:
                    print(f"格式化过期时间时出错: {str(e)}")
                    info['expiration_date'] = f"格式错误: {str(w.expiration_date)}"
            else:
                info['expiration_date'] = "未找到过期时间"
            
            # 如果没有获取到注册时间或过期时间，尝试使用系统whois命令
            if info['creation_date'] == "未找到注册时间" or info['expiration_date'] == "未找到过期时间":
                print("使用python-whois库未找到完整信息，尝试使用系统whois命令...")
                whois_text = get_whois_from_command(domain)
                if whois_text:
                    print("成功获取系统whois命令输出，正在解析...")
                    # 解析系统whois命令输出
                    if "Created" in whois_text and info['creation_date'] == "未找到注册时间":
                        for line in whois_text.split('\n'):
                            if "Created" in line or "Creation Date" in line or "created" in line:
                                parts = line.split(':', 1)
                                if len(parts) > 1:
                                    date_str = parts[1].strip()
                                    info['creation_date'] = date_str
                                    print(f"从系统whois命令中提取到注册时间: {date_str}")
                                    break
                    
                    if "Expiry" in whois_text or "Expiration" in whois_text and info['expiration_date'] == "未找到过期时间":
                        for line in whois_text.split('\n'):
                            if "Expiry" in line or "Expiration" in line or "expires" in line:
                                parts = line.split(':', 1)
                                if len(parts) > 1:
                                    date_str = parts[1].strip()
                                    info['expiration_date'] = date_str
                                    print(f"从系统whois命令中提取到过期时间: {date_str}")
                                    break
            
            return info
    except Exception as e:
        print(f"使用python-whois库查询失败: {str(e)}，尝试使用系统whois命令...")
        whois_text = get_whois_from_command(domain)
        if not whois_text:
            raise Exception("系统whois命令也失败了")
        
        print("成功获取系统whois命令输出，正在解析...")
        info = {
            'registrant': "未找到注册人信息",
            'organization': "未找到组织信息",
            'creation_date': "未找到注册时间",
            'expiration_date': "未找到过期时间"
        }
        
        # 解析系统whois命令输出
        for line in whois_text.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # 尝试提取注册人信息
            if "Registrant Name" in line or "registrant:" in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    info['registrant'] = parts[1].strip()
            
            # 尝试提取组织信息
            if "Registrant Organization" in line or "org:" in line or "Organization" in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    info['organization'] = parts[1].strip()
            
            # 尝试提取注册时间
            if "Created" in line or "Creation Date" in line or "created" in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    info['creation_date'] = parts[1].strip()
            
            # 尝试提取过期时间
            if "Expiry" in line or "Expiration" in line or "expires" in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    info['expiration_date'] = parts[1].strip()
        
        return info
    except TimeoutError:
        print("WHOIS查询超时")
        return {
            'registrant': "WHOIS查询超时",
            'organization': "WHOIS查询超时",
            'creation_date': "WHOIS查询超时",
            'expiration_date': "WHOIS查询超时"
        }
    except Exception as e:
        print(f"WHOIS查询错误: {str(e)}")
        return {
            'registrant': f"WHOIS查询错误: {str(e)}",
            'organization': f"WHOIS查询错误: {str(e)}",
            'creation_date': f"WHOIS查询错误: {str(e)}",
            'expiration_date': f"WHOIS查询错误: {str(e)}"
        }

def get_domain_registration_date(domain):
    """获取域名的注册时间"""
    try:
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                return w.creation_date[0].strftime("%Y-%m-%d")
            else:
                return w.creation_date.strftime("%Y-%m-%d")
        else:
            return "未找到注册时间"
    except Exception as e:
        return f"WHOIS查询错误: {str(e)}"

def check_ssl_certificate(domain):
    """检查域名的SSL证书安全性"""
    try:
        print(f"开始检查SSL证书: {domain}")
        # 创建SSL上下文
        context = ssl.create_default_context()
        # 设置超时时间
        socket.setdefaulttimeout(10)
        
        # 连接到服务器
        print(f"正在连接到 {domain}:443...")
        with socket.create_connection((domain, 443)) as sock:
            print(f"连接成功，正在进行SSL握手...")
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # 获取证书信息
                print(f"SSL握手成功，正在获取证书信息...")
                cert = ssock.getpeercert()
                
                # 提取证书信息
                print(f"正在解析证书信息...")
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                # 检查证书是否过期
                now = datetime.now()
                is_expired = now > not_after
                days_to_expire = (not_after - now).days
                
                # 检查证书颁发机构
                issuer_cn = issuer.get('commonName', 'Unknown')
                
                # 检查证书算法
                cipher = ssock.cipher()
                
                print(f"SSL证书信息解析完成")
                # 返回证书安全性信息
                return {
                    "status": "有效" if not is_expired else "已过期",
                    "issuer": issuer_cn,
                    "valid_from": not_before.strftime("%Y-%m-%d"),
                    "valid_to": not_after.strftime("%Y-%m-%d"),
                    "days_to_expire": days_to_expire,
                    "cipher": cipher[0],
                    "version": cipher[1],
                    "bits": cipher[2]
                }
    except ssl.SSLError as e:
        print(f"SSL错误: {str(e)}")
        return {"status": f"SSL错误: {str(e)}"}
    except socket.gaierror as e:
        print(f"DNS解析错误: {str(e)}")
        return {"status": f"DNS解析错误: {str(e)}"}
    except socket.timeout as e:
        print(f"连接超时: {str(e)}")
        return {"status": f"连接超时: {str(e)}"}
    except Exception as e:
        print(f"检查SSL证书时出错: {str(e)}")
        return {"status": f"检查SSL证书时出错: {str(e)}"}


# 删除重复的check_ssl_certificate函数

@timeout(20, "SSL检查超时")
def check_ssl_certificate_with_timeout(domain):
    """带超时的SSL证书检查"""
    return check_ssl_certificate(domain)

def get_domain_ip(domain):
    """获取域名对应的IP地址"""
    try:
        print(f"正在解析域名 {domain} 的IP地址...")
        ip_addresses = []
        
        # 使用socket.getaddrinfo获取所有IP地址
        addrinfo = socket.getaddrinfo(domain, 80, socket.AF_INET)
        for addr in addrinfo:
            ip = addr[4][0]
            if ip not in ip_addresses:
                ip_addresses.append(ip)
        
        if not ip_addresses:
            return "未找到IP地址"
        
        return ip_addresses
    except socket.gaierror as e:
        print(f"DNS解析错误: {str(e)}")
        return f"DNS解析错误: {str(e)}"
    except Exception as e:
        print(f"获取IP地址时出错: {str(e)}")
        return f"获取IP地址时出错: {str(e)}"

def get_ip_location(ip):
    """获取IP地址的归属地信息"""
    try:
        print(f"正在查询IP {ip} 的归属地信息...")
        # 使用ip-api.com的免费API
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = response.json()
        
        if data["status"] == "success":
            location = {
                "country": data.get("country", "未知"),
                "region": data.get("regionName", "未知"),
                "city": data.get("city", "未知"),
                "isp": data.get("isp", "未知"),
                "org": data.get("org", "未知")
            }
            return location
        else:
            return {"error": "查询失败", "message": data.get("message", "未知错误")}
    except requests.RequestException as e:
        print(f"请求IP归属地API时出错: {str(e)}")
        return {"error": "请求失败", "message": str(e)}
    except Exception as e:
        print(f"获取IP归属地信息时出错: {str(e)}")
        return {"error": "处理失败", "message": str(e)}

@timeout(15, "IP归属地查询超时")
def get_ip_location_with_timeout(ip):
    """带超时的IP归属地查询"""
    return get_ip_location(ip)

def calculate_registration_years(creation_date_str):
    """计算域名已注册的年数"""
    try:
        # 尝试解析注册日期字符串
        formats = [
            "%Y-%m-%d",
            "%d-%b-%Y",
            "%d.%m.%Y",
            "%Y.%m.%d",
            "%d/%m/%Y",
            "%Y/%m/%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%a %b %d %H:%M:%S %Y",
            "%d %b %Y",
            "%B %d %Y"
        ]
        
        creation_date = None
        for fmt in formats:
            try:
                creation_date = datetime.strptime(creation_date_str, fmt)
                break
            except ValueError:
                continue
        
        if not creation_date:
            return "无法解析注册日期"
        
        # 计算从注册日期到现在的年数
        now = datetime.now()
        years = now.year - creation_date.year
        
        # 如果当前月日小于注册月日，则减去1年
        if (now.month, now.day) < (creation_date.month, creation_date.day):
            years -= 1
            
        return years
    except Exception as e:
        print(f"计算注册年限时出错: {str(e)}")
        return "计算错误"

if __name__ == '__main__':
    targets = []

    try:
        with open('targets.txt', 'r', encoding='utf-8') as f:
            targets = f.readlines()
    except FileNotFoundError:
        print("错误: targets.txt 文件不存在")
        exit(1)
    except Exception as e:
        print(f"读取targets.txt时出错: {str(e)}")
        exit(1)

    results = []
    company_list = []
    errors = []
    
    total_domains = len([line for line in targets if line.strip()])
    processed_domains = 0
    
    for i, line in enumerate(targets):
        domain = line.rstrip('\n')
        if not domain:
            continue
            
        processed_domains += 1
        try:
            print(f"\n[{processed_domains}/{total_domains}] 正在查询域名: {domain}")
            print("-" * 50)
            
            # 获取域名WHOIS信息
            print(f"正在获取WHOIS信息...")
            domain_info = get_domain_info(domain)
            
            # 检查SSL证书
            print(f"正在检查SSL证书安全性...")
            try:
                ssl_info = check_ssl_certificate_with_timeout(domain)
            except TimeoutError:
                print("SSL证书检查超时")
                ssl_info = {"status": "SSL证书检查超时"}
            except Exception as e:
                print(f"SSL证书检查出错: {str(e)}")
                ssl_info = {"status": f"SSL证书检查出错: {str(e)}"}
            
            # 格式化SSL证书信息
            ssl_status = "未检测到SSL证书"
            if isinstance(ssl_info, dict):
                if "status" in ssl_info:
                    if ssl_info["status"].startswith("SSL错误") or ssl_info["status"].startswith("DNS解析错误") or ssl_info["status"].startswith("连接超时") or ssl_info["status"].startswith("检查SSL证书时出错") or ssl_info["status"].startswith("SSL证书检查超时") or ssl_info["status"].startswith("SSL证书检查出错"):
                        ssl_status = ssl_info["status"]
                    else:
                        ssl_status = f"状态: {ssl_info['status']}, 颁发者: {ssl_info['issuer']}, 有效期: {ssl_info['valid_from']} 至 {ssl_info['valid_to']}, 剩余天数: {ssl_info['days_to_expire']}, 加密算法: {ssl_info['cipher']}"
            
            # 获取域名IP地址
            print(f"正在获取域名IP地址...")
            ip_addresses = get_domain_ip(domain)
            print(f"获取到的IP地址: {ip_addresses}")
    
            # 获取IP归属地信息
            ip_location_info = ""
            if isinstance(ip_addresses, list) and ip_addresses:
                for ip in ip_addresses:
                    print(f"正在获取IP {ip} 的归属地信息...")
                    try:
                        location = get_ip_location_with_timeout(ip)
                        print(f"IP {ip} 归属地查询结果: {location}")
                        if isinstance(location, dict) and "error" not in location:
                            ip_location_info += f"IP: {ip}, 国家: {location.get('country', '未知')}, 地区: {location.get('region', '未知')}, 城市: {location.get('city', '未知')}, ISP: {location.get('isp', '未知')}, 组织: {location.get('org', '未知')}\n"
                        else:
                            error_msg = location.get("message", "未知错误") if isinstance(location, dict) else "查询失败"
                            ip_location_info += f"IP: {ip}, 归属地查询失败: {error_msg}\n"
                    except Exception as e:
                        print(f"获取IP {ip} 归属地信息时出错: {str(e)}")
                        ip_location_info += f"IP: {ip}, 归属地查询出错: {str(e)}\n"
            else:
                error_msg = ip_addresses if isinstance(ip_addresses, str) else "未知错误"
                print(f"IP地址获取失败: {error_msg}")
                ip_location_info = f"IP地址获取失败: {error_msg}\n"
            
            # 计算注册年限
            registration_years = "未知"
            if domain_info['creation_date'] != "未找到注册时间" and "WHOIS查询错误" not in domain_info['creation_date'] and "WHOIS查询超时" not in domain_info['creation_date']:
                registration_years = calculate_registration_years(domain_info['creation_date'])
            
            # 组合结果
            result_text = f"域名: {domain}\n"
            result_text += f"注册人: {domain_info['registrant']}\n"
            result_text += f"组织/公司: {domain_info['organization']}\n"
            result_text += f"注册时间: {domain_info['creation_date']}\n"
            result_text += f"注册年限: {registration_years}年\n"
            result_text += f"过期时间: {domain_info['expiration_date']}\n"
            result_text += f"SSL证书: {ssl_status}\n"
            result_text += f"IP归属地信息:\n{ip_location_info}\n"
            
            results.append(result_text)
            print("-" * 50)
            print("查询结果:")
            print(result_text)
            
            # 保存公司名称到列表
            if domain_info['organization'] != "未找到组织信息" and "WHOIS查询错误" not in domain_info['organization'] and "WHOIS查询超时" not in domain_info['organization']:
                company_list.append(domain_info['organization'] + '\n')
                
        except Exception as e:
            error_msg = f"{domain}: 错误 - {str(e)}"
            print(f"处理域名时出错: {error_msg}")
            errors.append(error_msg + '\n')
            continue
            
        # 每查询5个域名休眠一下，避免被限制
        if processed_domains % 5 == 0 and processed_domains < total_domains:
            sleep_time = random.randint(2, 5)
            print(f"已查询{processed_domains}个域名，休眠{sleep_time}秒...")
            time.sleep(sleep_time)
        
    print(f"\n查询完成，共查询{len(results)}个域名，{len(errors)}个错误")
    
    # 保存结果
    try:
        with open('results.txt', 'w', encoding='utf-8') as f:
            f.writelines(results)
        print(f"结果已保存到 results.txt")
        
        with open('company_list.txt', 'w', encoding='utf-8') as f:
            f.writelines(company_list)
        print(f"公司列表已保存到 company_list.txt")
        
        if errors:
            with open('errors.txt', 'w', encoding='utf-8') as f:
                f.writelines(errors)
            print(f"错误信息已保存到 errors.txt")
    except Exception as e:
        print(f"保存结果时出错: {str(e)}")