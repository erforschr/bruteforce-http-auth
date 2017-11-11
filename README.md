# Bruteforce HTTP Authentication


### Warning

/!\ Not adequately tested /!\ 



### Description

Simple tool to bruteforce HTTP authentication forms.

Supports:
* Basic HTTP authentication
* Digest HTTP authentication
* NTLM authentication



### Usage

Usage example:
```sh
python3 bruteforce-http-auth.py -T targets_file -U usernames_file -P passwords_file --verbose
```

Output example:

```sh
[10-00-43] --------------------------
[10-00-43] ~  Bruteforce HTTP Auth  ~
[10-00-43] --------------------------
[10-00-43] 
[10-00-43] Included in bruteforce scope:
[10-00-43] 
[10-00-43] => URL: https://www.my-first-protected-resource.com
[10-00-43]    Status code: 401
[10-00-43]    Server: Apache/2.4.18 (Ubuntu)
[10-00-43]    Date: Sat, 11 Nov 2017 10:00:40 GMT
[10-00-43]    Authentication type: basic
[10-00-43] 
[10-00-43] => URL: https://www.my-second-protected-resource.com
[10-00-43]    Status code: 401
[10-00-43]    Server: Apache/2.4.18 (Ubuntu)
[10-00-43]    Date: Sat, 11 Nov 2017 10:00:40 GMT
[10-00-43]    Authentication type: basic
[10-00-43] 
[10-00-43] Excluded from bruteforce scope:
[10-00-43] 
[10-00-43] => URL: https://www.my-third-unprotected-resource.com
[10-00-43]    Status code: 200
[10-00-43]    Server: Apache/2.4.18 (Ubuntu)
[10-00-43]    Date: Sat, 11 Nov 2017 10:00:40 GMT
[10-00-43]    Authentication type: None
[10-00-43]
[10-00-43] Launch bruteforce on included targets [y/N] ? y
[10-00-45] 
[10-00-45] Authentication failed: Username: "user1" Password: "pass2" URL: https://www.my-first-protected-resource.com
[10-00-45] Authentication failed: Username: "user2" Password: "pass1" URL: https://www.my-first-protected-resource.com
[10-00-45] Authentication failed: Username: "user1" Password: "pass1" URL: https://www.my-first-protected-resource.com
[10-00-45] Authentication successful: Username: "user2" Password: "pass2" URL: https://www.my-first-protected-resource.com
[10-00-45] Authentication failed: Username: "user3" Password: "pass1" URL: https://www.my-first-protected-resource.com
[10-00-45] Authentication failed: Username: "user3" Password: "pass2" URL: https://www.my-first-protected-resource.com
[10-00-46] Authentication successful: Username: "user1" Password: "pass1" URL: https://www.my-second-protected-resource.com
[10-00-46] Authentication failed: Username: "user1" Password: "pass2" URL: https://www.my-second-protected-resource.com
[10-00-46] Authentication failed: Username: "user2" Password: "pass1" URL: https://www.my-second-protected-resource.com
[10-00-46] Authentication failed: Username: "user2" Password: "pass2" URL: https://www.my-second-protected-resource.com
[10-00-46] Progress : 10
[10-00-46] Authentication failed: Username: "user3" Password: "pass1" URL: https://www.my-second-protected-resource.com
[10-00-46] Authentication failed: Username: "user3" Password: "pass2" URL: https://www.my-second-protected-resource.com
[10-00-46] Progress : 12 (end)
[10-00-46] 
[10-00-46] Finished
```

Arguments:
```sh
  -t TARGET, --target TARGET
                        URL
                        
  -T TARGETFILE, --targetfile TARGETFILE
                        File of URL
                        
  -u USERNAME, --username USERNAME
                        Username ("username" or "username:password")
                        
  -U USERNAMESFILE, --usernamesfile USERNAMESFILE
                        File of usernames ("username" or "username:password")
                        
  -p PASSWORD, --password PASSWORD
                        Password
                        
  -P PASSWORDSFILE, --passwordsfile PASSWORDSFILE
                        File of passwords
                        
  -w WORKERS, --workers WORKERS
                        Number of threads (interger between 1 and 100)
                        
  -o ORDER, --order ORDER
                        Targets order ("serie" or "parallel")
                        
  -v, --verbose         Verbose
```



##### NTLM authentication

Usernames format for NTLM authentication: `domain\username`

/!\ Be aware that a NTLM authentication bruteforce could lock an account. /!\



### Requirements
Python libs required:
* [requests](https://github.com/kennethreitz/requests)
* [requests_ntlm](https://github.com/requests/requests-ntlm)
* [validators](https://github.com/kvesteri/validators)

Install:
```sh
python3 -m pip install -r requirements.txt
```


### Dictionaries

| List                                            | Source               | Link                                                                                                    |
|-------------------------------------------------|----------------------|---------------------------------------------------------------------------------------------------------|
| unix_users.txt                                  | Metasploit wordlists | https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/unix_users.txt                |
| unix_passwords.txt                              | Metasploit wordlists | https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/unix_passwords.txt            |
| seclists_usernames_top_shortlist.txt            | SecLists             | https://github.com/danielmiessler/SecLists/blob/master/Usernames/top_shortlist.txt                      |
| seclists_passwords_top_shortlist.txt            | SecLists             | https://github.com/danielmiessler/SecLists/blob/master/Passwords/top_shortlist.txt                      |
| seclists_10_million_password_list_top_100.txt   | SecLists             | https://github.com/danielmiessler/SecLists/blob/master/Passwords/10_million_password_list_top_100.txt   |
| seclists_10_million_password_list_top_500.txt   | SecLists             | https://github.com/danielmiessler/SecLists/blob/master/Passwords/10_million_password_list_top_500.txt   |
| seclists_10_million_password_list_top_1000.txt  | SecLists             | https://github.com/danielmiessler/SecLists/blob/master/Passwords/10_million_password_list_top_1000.txt  |
| seclists_10_million_password_list_top_10000.txt | SecLists             | https://github.com/danielmiessler/SecLists/blob/master/Passwords/10_million_password_list_top_10000.txt |
| custom_common_web_services_usernames_short.txt  | N/A            		 | 																										   |
| custom_common_web_services_usernames_medium.txt | N/A           		 | 																										   |
| custom_common_web_services_passwords_short.txt  | N/A           		 | 																										   |
| custom_common_web_services_passwords_medium.txt | N/A            		 | 																										   |
| custom_tomcat_userpass.list 					  | N/A          		 | 																										   |
| custom_jboss_userpass.list				      | N/A          		 | 																										   |
