import requests
import base64
import pyaes
import re

# 解密函数（AES-CBC 模式）
def decrypt_aes_cbc(encrypted_text, key, iv):
    encrypted_bytes = base64.b64decode(encrypted_text)
    
    if len(encrypted_bytes) % 16 != 0:
        return None
    
    aes = pyaes.AESModeOfOperationCBC(key.encode('utf-8'), iv.encode('utf-8'))
    decrypted_data = b''.join(aes.decrypt(encrypted_bytes[i:i+16]) for i in range(0, len(encrypted_bytes), 16))
    
    return decrypted_data[:-decrypted_data[-1]].decode('utf-8')

# 提取 SS 数据并格式化
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

# 请求并解密 API 数据
def fetch_and_decrypt():
    url = "http://cnc07api.cnc07.com/api/cnc07iuapis"
    key = "1kv10h7t*C3f8c@$"
    iv = "@$6l&bxb5n35c2w9"

    response = requests.get(url, timeout=10)
    response.raise_for_status()
    
    encrypted_servers = response.json().get('servers')
    decrypted_data = decrypt_aes_cbc(encrypted_servers, key, iv)
    
    return extract_and_format_data(decrypted_data) if decrypted_data else []

# 主函数
def main():
    results = fetch_and_decrypt()
    
    # 打印结果到终端
    for result in results:
        print(result)
    
    # 保存结果到 output.txt
    with open("output.txt", "w", encoding="utf-8") as f:
        for result in results:
            f.write(result + "\n")

if __name__ == "__main__":
    main()
