import requests
import os

# 设置环境变量来允许不安全的传统重协商
os.environ['OPENSSL_CONF'] = '/dev/null'

# 创建会话
session = requests.Session()

# 尝试不同的请求头组合
header_combinations = [
    # 标准浏览器头
    {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Referer': 'https://nbowx-cloud-nbo.spdb.com.cn:9527/',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    },
    # 简化的头
    {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Referer': 'https://nbowx-cloud-nbo.spdb.com.cn:9527/'
    },
    # 模拟移动设备
    {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
        'Referer': 'https://nbowx-cloud-nbo.spdb.com.cn:9527/'
    }
]

# 尝试不同的URL路径
url_variations = [
    'https://nbowx-cloud-nbo.spdb.com.cn:9527/my-js/axios.min.map',
    'https://nbowx-cloud-nbo.spdb.com.cn:9527/my-js/axios.min.js.map',
    'https://nbowx-cloud-nbo.spdb.com.cn:9527/my-js/axios.map'
]

# 尝试所有组合
for url in url_variations:
    print(f"\nTrying URL: {url}")
    for i, headers in enumerate(header_combinations):
        print(f"  Attempt {i+1} with headers:", headers)
        try:
            response = session.get(url, headers=headers, verify=False, timeout=10)
            print(f"    Status code: {response.status_code}")
            print(f"    Headers: {dict(response.headers)}")
            print(f"    Content length: {len(response.content)}")
            if response.content:
                print("    Content preview:", response.content[:500])
            if response.status_code == 200:
                print("    SUCCESS!")
                exit()
        except Exception as e:
            print(f"    Error: {e}")
