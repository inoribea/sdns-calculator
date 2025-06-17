# sdns-calculator

DNS Stamp calculator component for Python. This tool generates DNS Stamps (for DoH/DoT/DoQ) by retrieving server certificates and computing necessary hashes locally.

**Note:** This tool requires an active internet connection to retrieve the server's SSL/TLS certificate, which is essential for generating the DNS Stamp. The calculation of the DNS Stamp itself is performed locally after the certificate is obtained.

- Thanks to jedisct1.
- Code implementations sourced from [stamps-specifications](https://dnscrypt.info/stamps-specifications/)  
## Why
This project was created to provide a local solution for generating DNS Stamps, particularly when direct certificate and hash computation through tools like dnscrypt-proxy is challenging. It aims to fill the gap for users seeking a straightforward, script-based approach.
## Use
1.  Install Python (3.7+)
2.  Install the `cryptography` Python module: `pip install cryptography`
3.  Download the script for your language (e.g., `sdns-calculator.py`)
4.  Run it from your terminal: `python sdns-calculator.py`

**Important Note for Windows Users:**
If you encounter an `ImportError: DLL load failed while importing _rust: The specified procedure could not be found.` error when running the script, it is highly likely that your system is missing or has an outdated **Microsoft Visual C++ Redistributable** package. The `cryptography` library, which `sdns-calculator` depends on for secure operations, relies on these runtime components.
To resolve this issue:
1.  **Download and install the latest Microsoft Visual C++ Redistributable**
    *   You can find the official download here: [Microsoft Visual C++ Redistributable](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist)
    *   It's generally recommended to download and install both the `x86` and `x64` versions, even if your Python installation is 64-bit, to ensure full compatibility.
2.  **Restart your computer** after installation to ensure the changes take effect system-wide.
3.  (Optional but recommended) If you've already tried to run the script and encountered the error *before* installing the redistributable, it's a good idea to reinstall `cryptography` after installing the redistributable: `pip install --force-reinstall cryptography`

If you encounter any problems during use, please submit your issues.
