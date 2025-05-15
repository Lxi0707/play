import requests
import base64
import pyaes
import re
import os
import json

def decrypt_aes_cbc(encrypted_text, key, iv):
    encrypted_bytes = base64.b64decode(encrypted_text)
    
    if len(encrypted_bytes) % 16 != 0:
        return None
    
    aes = pyaes.AESModeOfOperationCBC(key.encode('utf-8'), iv.encode('utf-8'))
    decrypted_data = b''.join(aes.decrypt(encrypted_bytes[i:i+16]) for i in range(0, len(encrypted_bytes), 16))
    
    return decrypted_data[:-decrypted_data[-1]].decode('utf-8')

def extract_and_format_data(decrypted_data):
    ss_pattern = re.compile(r'SS = ss, ([\d.]+), (\d+),encrypt-method=([\w-]+),password=([\w\d]+)')
    matches = ss_pattern.findall(decrypted_data)
    
    results = []
    for ip, port, method, password in matches:
        formatted_data = f"{method}:{password}@{ip}:{port}"
        base64_encoded_data = base64.urlsafe_b64encode(formatted_data.encode('utf-8')).decode('utf-8')
        
        city = re.search(rf'{ip}.*?"city":"([^"]+)"', decrypted_data)
        city_name = city.group(1) if city else "Unknown"
        
        results.append(f"ss://{base64_encoded_data}#{city_name}")
    
    return results

def fetch_and_decrypt():
    url = os.getenv('API_URL', "http://cnc07api.cnc07.com/api/cnc07iuapis")
    key = os.getenv('DECRYPT_KEY', "1kv10h7t*C3f8c@$")
    iv = os.getenv('DECRYPT_IV', "@$6l&bxb5n35c2w9")

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        encrypted_servers = response.json().get('servers')
        decrypted_data = decrypt_aes_cbc(encrypted_servers, key, iv)
        
        return extract_and_format_data(decrypted_data) if decrypted_data else []
    except Exception as e:
        print(f"获取或解密数据时出错: {e}")
        return []

def main():
    results = fetch_and_decrypt()
    
    # GitHub Actions专用输出
    if 'GITHUB_ACTIONS' in os.environ:
        # 为GitHub Actions设置输出
        print(f"::set-output name=results::{json.dumps(results)}")
        
        # 写入文件作为工件
        with open('ss_results.txt', 'w') as f:
            f.write('\n'.join(results))
    else:
        # 本地运行时的普通输出
        for result in results:
            print(result)

if __name__ == "__main__":
    main()
