# sdns-calculator

DNS Stamp calculator component for Python, A simple DNS Stamp (DoH/DoT/DoQ) generation tool.

**If you believe that generating your DNS Stamp online poses security risks, consider this open-source project. The calculation process is entirely local, ensuring no risk of data leakage.**

- Thanks for jedisct1 and qwq-plus  
- Code implementations sourced from [stamps-specifications](https://dnscrypt.info/stamps-specifications/)  
## Why
I cannot properly obtain the certificate and compute the hash for the compute server through dnscrypt-proxy. When I have this trouble, I have not found a suitable local solution, which prompted me to use AI to generate this code.
## Use
1.Install Python  
2.Importing cryptography Python modules  
3.Download scripts for your language  
4.Run it!  

**Important Note for Windows Users:**
If you encounter an `ImportError: DLL load failed while importing _rust: The specified procedure could not be found.` error when running the script, it is highly likely that your system is missing or has an outdated **Microsoft Visual C++ Redistributable** package. The `cryptography` library, which `sdns-calculator` depends on for secure operations, relies on these runtime components.
To resolve this issue:
1.  **Download and install the latest Microsoft Visual C++ Redistributable**
    *   You can find the official download here: [Microsoft Visual C++ Redistributable](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist)
    *   It's generally recommended to download and install both the `x86` and `x64` versions, even if your Python installation is 64-bit, to ensure full compatibility.
2.  **Restart your computer** after installation to ensure the changes take effect system-wide.
3.  (Optional but recommended) If you've already tried to run the script and encountered the error *before* installing the redistributable, it's a good idea to reinstall `cryptography` after installing the redistributable:

If you encounter any problems during use, please submit your issues
