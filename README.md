# HTTP Authentication Bruteforcer

/!\ Not fully functionnal yet /!\
/!\ Not tested /!\

### Description

Simple tool to brutefore HTTP authentication forms.

Currently supports:
* Basic HTTP authentication
* Digest HTTP authentication

### Usage

```sh
python3 httpauthbruteforcer.py -c /tmp/userpass.txt -a basic https://www.my-protected-resource.com/
```

### Requirements
Python libs required:
* requests
* grequests
* validators

