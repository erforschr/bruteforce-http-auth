# HTTP Authentication Bruteforcer

/!\ Not fully functionnal yet /!\

/!\ Not tested /!\

### Description

Simple tool to brutefore HTTP authentication forms.

Currently supports:
* Basic HTTP authentication
* Digest HTTP authentication

### Usage

Usage:
```sh
python3 httpauthbruteforcer.py -c /tmp/credentials.txt -a basic https://www.my-protected-resource.com/
```

Output:
```sh
-------------------------
~ HTTP Auth Bruteforcer ~
-------------------------

URL: https://www.my-protected-resource.com/
Response status code: 401
Server: Apache/2.4.12 (Ubuntu)
Date: Sat, 28 Jan 2017 20:27:10 GMT
Authentication type: Basic
Authentication information: realm:Restricted Content

Authentication tests begin...
Date: 21:25:18 28/01/2017

Authentication attempts: 10
Authentication attempts: 20
Authentication attempts: 30
Authentication attempts: 40
Authentication attempts: 50
Authentication attempts: 60
Authentication success. Username: username, password: password
Authentication attempts: 70
Authentication attempts: 80
Authentication attempts: 84

Authentication tests finished.
Date: 21:25:23 28/01/2017
```

### Requirements
Python libs required:
* requests
* grequests
* validators
