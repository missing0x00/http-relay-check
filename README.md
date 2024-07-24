# http-relay-check
A tool for checking HTTP servers to see if they may be vulnerable to NTLM relay attacks. In order to prevent NTLM relay, IIS servers must both use HTTPS and **require** Channel Binding Tokens (CBT). The configuration enabling CBT is also known as Extended Protection for Authentication (EPA).

The script will send one authentication request with CBT enabled, and one with CBT disabled. It will **attempt** to watch for invalid responses with the first request to avoid account lockouts.

If the authentication request without CBT succeeds, this indicates that the server is configured with CBT/EPA Disabled or Enabled, but not Required.

## Installation
### Python3 virtualenv
```
git clone https://github.com/missing0x00/http-relay-check
cd http-relay-check
virtualenv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 http-relay-check.py -h
```

## Usage
Provide target URL and valid domain user credentials to authenticate.
```commandline
usage: http-relay-check.py [-h] -u USERNAME -d DOMAIN -p PASSWORD url

positional arguments:
  url          Target URL

options:
  -h, --help   show this help message and exit
  -u USERNAME  Username
  -d DOMAIN    AD Domain
  -p PASSWORD  Password
```

#### Example: ADCS ESC8 Verification

```commandline
python3 http-relay-check.py https://CA.domain.local/CertSrv/certfnsh.asp -d domain.local -u username -p password
```

## Troubleshooting
```commandline
Access denied: Server did not respond with NTLM challenge token
```
Target URL does not support NTLM; may require Kerberos authentication.

## References
 - [Microsoft](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/windowsauthentication/extendedprotection/)  - Extended Protection documentation
 - [@HackAndDo](https://twitter.com/HackAndDo) - [NTLM relay](https://en.hackndo.com/ntlm-relay/#tls-binding) - Detailed explanation of TLS Binding
 - [@zyn3rgy](https://twitter.com/zyn3rgy) - [LdapRelayScan](https://github.com/zyn3rgy/LdapRelayScan) - Inspiration for this tool
 - [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) - ADCS attacks including ESC8 - HTTP NTLM relay
 - [Impacket](https://github.com/fortra/impacket) - ntlmrelayx