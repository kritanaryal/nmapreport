


## 🛠️ Nmap Tool
   - Nmap (v7.95)

```bash
namp -p 22,80,443 -sV -O --script vuln 192.168.1.1
```
 -  -p : Scan specific ports
 -  -sV : Detect service versions
 -  -o : 	OS detection
 -  --script : Runs the Nmap Scripting Engine (NSE) with the vuln category, checking for known vulnerabilities on the detected services

      ## Here is the result :
       Nmap 7.95 scan initiated Tue Jul 22 13:15:14 2025 as: /usr/lib/nmap/nmap --privileged -p 22,80,443 -sV -O --script vuln -oN forgithubproject.txt 192.168.1.1
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.1.1 (192.168.1.1)
Host is up (0.0019s latency).

| PORT  |  STATE | SERVICE | VERSION |
|--------|--------|---------|---------|
| 22/tcp | closed | ssh     |
| 80/tcp | open   | http    |

|_http-server-header: <empty>
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Cache-Control: no-cache,no-store
|     Pragma: no-cache
|     Content-Length: 154266
|     Set-Cookie: SID=d5fae5f7d71909afd2b57b34c68a6f9e0cb98155c4f7bc8f648ee242b96b071c; PATH=/; HttpOnly; SameSite=strict
|     Set-Cookie: _TESTCOOKIESUPPORT=1; PATH=/; HttpOnly; SameSite=strict
|     Server: 
|     Accept-Ranges: bytes
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: frame-ancestors 'self' 
|     X-Frame-Options: SAMEORIGIN
|     Content-Type: text/html; charset=utf-8
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <link rel="shortcut icon" href="/img/favicon.ico" />
|     <title>&#70;&#54;&#54;&#50;&#48;</title>
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     X-Frame-Options: SAMEORIGIN
|     Content-Security-Policy: frame-ancestors 'self'; 
|     Cache-Control: no-cache,no-store
|     Pragma: no-cache
|     <html>
|     <head><title>400 Bad Request</title></head>
|     <body bgcolor="#FFFFFF" text="#000000" link="#2020ff" vlink="#4040cc">
|     <h2>400 Bad Request</h2>
|     Your request has bad syntax or is inherently impossible to satisfy.
|     <div style="display:none">
|     <ajax_response_xml_root>
|     <IF_ERRORSTR>SessionTimeout</IF_ERRORSTR>
|     <IF_ERRORPARAM>SUCC</IF_ERRORPARAM>
|     <IF_ERRORTYPE>SUCC</IF_ERRORTYPE>
|_    </ajax_response_xml_roo
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-internal-ip-disclosure: ERROR: Script execution failed (use -d to debug)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
443/tcp open   ssl/https
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: <empty>
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     X-Frame-Options: SAMEORIGIN
|     Content-Security-Policy: frame-ancestors 'self'; 
|     Cache-Control: no-cache,no-store
|     Pragma: no-cache
|     <html>
|     <head><title>404 Not Found</title></head>
|     <body bgcolor="#FFFFFF" text="#000000" link="#2020ff" vlink="#4040cc">
|     <h2>404 Not Found</h2>
|     <span>The requested URL was not found on this server.</span>
|     <div style="display:none">
|     <ajax_response_xml_root>
|     <IF_ERRORSTR>SessionTimeout</IF_ERRORSTR>
|     <IF_ERRORPARAM>SUCC</IF_ERRORPARAM>
|     <IF_ERRORTYPE>SUCC</IF_ERRORTYPE>
|     </ajax_response_xml_root>
|     <span>Padd
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Cache-Control: no-cache,no-store
|     Pragma: no-cache
|     Content-Length: 154266
|     Set-Cookie: SID_HTTPS_=cdad93264b43842c2d3679b196c4a11cc1d5a6319598bb34779a5dacdb818da4; PATH=/; Secure; HttpOnly; SameSite=strict
|     Set-Cookie: _TESTCOOKIESUPPORT_HTTPS_=1; PATH=/; Secure; HttpOnly; SameSite=strict
|     Server: 
|     Accept-Ranges: bytes
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Content-Security-Policy: frame-ancestors 'self' 
|     X-Frame-Options: SAMEORIGIN
|     Content-Type: text/html; charset=utf-8
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <link rel="shortcut icon" href="/img/favicon.ico" />
|_    <title>&#70;&
|_ssl-ccs-injection: No reply from server (TIMEOUT)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.95%I=7%D=7/22%Time=687F3E2F%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,34ED,"HTTP/1\.0\x20200\x20OK\r\nConnection:\x20close\r\nCache-Co
SF:ntrol:\x20no-cache,no-store\r\nPragma:\x20no-cache\r\nContent-Length:\x
SF:20154266\r\nSet-Cookie:\x20SID=d5fae5f7d71909afd2b57b34c68a6f9e0cb98155
SF:c4f7bc8f648ee242b96b071c;\x20PATH=/;\x20HttpOnly;\x20SameSite=strict\r\
SF:nSet-Cookie:\x20_TESTCOOKIESUPPORT=1;\x20PATH=/;\x20HttpOnly;\x20SameSi
SF:te=strict\r\nServer:\x20\r\nAccept-Ranges:\x20bytes\r\nX-Content-Type-O
SF:ptions:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nContent-
SF:Security-Policy:\x20frame-ancestors\x20'self'\x20\r\nX-Frame-Options:\x
SF:20SAMEORIGIN\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\n\r\n<!D
SF:OCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01\x20Transitio
SF:nal//EN\"\x20\"http://www\.w3\.org/TR/html4/transitional\.dtd\">\n<html
SF:\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\n<head>\n<meta\x20http-eq
SF:uiv=\"Content-Type\"\x20content=\"text/html;\x20charset=utf-8\"\x20/>\n
SF:<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\">\n\n<lin
SF:k\x20rel=\"shortcut\x20icon\"\x20href=\"/img/favicon\.ico\"\x20/>\n\n<t
SF:itle>&#70;&#54;&#54;&#50;&#48;</title>\n<s")%r(HTTPOptions,5C7,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x2
SF:0text/html;\x20charset=iso-8859-1\r\nX-Content-Type-Options:\x20nosniff
SF:\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Frame-Options:\x20SAMEOR
SF:IGIN\r\nContent-Security-Policy:\x20frame-ancestors\x20'self';\x20\r\nC
SF:ache-Control:\x20no-cache,no-store\r\nPragma:\x20no-cache\r\n\r\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<html>\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<head><t
SF:itle>400\x20Bad\x20Request</title></head>\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20<body\x20bgcolor=\"#FFFFFF\"\x20t
SF:ext=\"#000000\"\x20link=\"#2020ff\"\x20vlink=\"#4040cc\">\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<h2>400\x20Bad\x2
SF:0Request</h2>\nYour\x20request\x20has\x20bad\x20syntax\x20or\x20is\x20i
SF:nherently\x20impossible\x20to\x20satisfy\.\n<div\x20style=\"display:non
SF:e\">\n<ajax_response_xml_root>\n<IF_ERRORSTR>SessionTimeout</IF_ERRORST
SF:R>\n<IF_ERRORPARAM>SUCC</IF_ERRORPARAM>\n<IF_ERRORTYPE>SUCC</IF_ERRORTY
SF:PE>\n</ajax_response_xml_roo");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port443-TCP:V=7.95%T=SSL%I=7%D=7/22%Time=687F3E32%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,4223,"HTTP/1\.0\x20200\x20OK\r\nConnection:\x20close\r\nC
SF:ache-Control:\x20no-cache,no-store\r\nPragma:\x20no-cache\r\nContent-Le
SF:ngth:\x20154266\r\nSet-Cookie:\x20SID_HTTPS_=cdad93264b43842c2d3679b196
SF:c4a11cc1d5a6319598bb34779a5dacdb818da4;\x20PATH=/;\x20Secure;\x20HttpOn
SF:ly;\x20SameSite=strict\r\nSet-Cookie:\x20_TESTCOOKIESUPPORT_HTTPS_=1;\x
SF:20PATH=/;\x20Secure;\x20HttpOnly;\x20SameSite=strict\r\nServer:\x20\r\n
SF:Accept-Ranges:\x20bytes\r\nX-Content-Type-Options:\x20nosniff\r\nX-XSS-
SF:Protection:\x201;\x20mode=block\r\nContent-Security-Policy:\x20frame-an
SF:cestors\x20'self'\x20\r\nX-Frame-Options:\x20SAMEORIGIN\r\nContent-Type
SF::\x20text/html;\x20charset=utf-8\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20
SF:\"-//W3C//DTD\x20HTML\x204\.01\x20Transitional//EN\"\x20\"http://www\.w
SF:3\.org/TR/html4/transitional\.dtd\">\n<html\x20xmlns=\"http://www\.w3\.
SF:org/1999/xhtml\">\n<head>\n<meta\x20http-equiv=\"Content-Type\"\x20cont
SF:ent=\"text/html;\x20charset=utf-8\"\x20/>\n<meta\x20http-equiv=\"X-UA-C
SF:ompatible\"\x20content=\"IE=edge\">\n\n<link\x20rel=\"shortcut\x20icon\
SF:"\x20href=\"/img/favicon\.ico\"\x20/>\n\n<title>&#70;&")%r(FourOhFourRe
SF:quest,5BA,"HTTP/1\.0\x20404\x20Not\x20Found\r\nConnection:\x20close\r\n
SF:Content-Type:\x20text/html;\x20charset=iso-8859-1\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Frame-Op
SF:tions:\x20SAMEORIGIN\r\nContent-Security-Policy:\x20frame-ancestors\x20
SF:'self';\x20\r\nCache-Control:\x20no-cache,no-store\r\nPragma:\x20no-cac
SF:he\r\n\r\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20<html>\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20<head><title>404\x20Not\x20Found</title></head>\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<body\x20bgcolor=\"
SF:#FFFFFF\"\x20text=\"#000000\"\x20link=\"#2020ff\"\x20vlink=\"#4040cc\">
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<h2
SF:>404\x20Not\x20Found</h2>\n<span>The\x20requested\x20URL\x20was\x20not\
SF:x20found\x20on\x20this\x20server\.</span>\n<div\x20style=\"display:none
SF:\">\n<ajax_response_xml_root>\n<IF_ERRORSTR>SessionTimeout</IF_ERRORSTR
SF:>\n<IF_ERRORPARAM>SUCC</IF_ERRORPARAM>\n<IF_ERRORTYPE>SUCC</IF_ERRORTYP
SF:E>\n</ajax_response_xml_root>\n<span>Padd");
MAC Address: 28:77:77:48:70:B2 (zte)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 22 13:17:16 2025 -- 1 IP address (1 host up) scanned in 122.09 seconds

    
