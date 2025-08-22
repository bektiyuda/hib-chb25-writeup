# Nginx ACL Bypass + SSRF to RCE Write-up

## Challenge Overview

The challenge provided a website along with its source code. When accessing the website, a 403 Access Denied error appeared.

## Initial Access

### Admin Authentication

To gain admin access, I needed to:
1. Enter username and password
2. Check the "Request Administrator Access" option

![](<img/1.png>)

After successful authentication, I found a "Fetch New SCP Data" button and some SCP data that didn't seem particularly important.

## Nginx ACL Bypass

### Identifying the Block

![](<img/2.png>)

When clicking the "Fetch" button, the web redirected to the `/admin/fetch-scp` endpoint. However, this endpoint was blocked not by the website's backend, but by the nginx web server. The ACL rules in `nginx.conf` explicitly denied all connections to the `/admin/fetch-scp` endpoint.

### Exploitation Technique

![](<img/3.png>)

Using a technique referenced from [HTB: Skyfall | 0xdf hacks stuff](https://0xdf.gitlab.io/2024/04/27/htb-skyfall.html), I was able to exploit the ACL rules by adding the `\x85` character at the end of the endpoint.

**Exploitation Steps using Burp Suite Repeater:**
![](<img/4.png>)

1. Add a random character at the end of the endpoint
2. Replace the hex value of that character with `85`

![alt text](img/4_1.png)

This successfully bypassed the nginx ACL rules and allowed access to the `/admin/fetch-scp` endpoint.

## SSRF Discovery and Analysis

### Source Code Analysis

![](<img/5.png>)

From the source code, the `/admin/fetch-scp` endpoint can fetch data from user-provided URLs, but the hostname must be `scp-anomaly.com`.

![](<img/6.png>)

I also discovered an interesting endpoint `/vault` that opens a `secret.txt` file. However, this endpoint rejects all requests not originating from `127.0.0.1`. To access `secret.txt`, the password `'p4ssw0rdnya_H1b_Jay4_J4ya'` is required as a query parameter.

**Target SSRF payload:** `127.0.0.1/vault?password=p4ssw0rdnya_H1b_Jay4_J4ya`

### Initial SSRF Attempts

![](<img/6_1.png>)

I first tried fetching the `/vault` endpoint through `scp-anomaly.com`, but it failed with a "Name or service not known" error because `scp-anomaly.com` wasn't mapped to any IP address (I hoped it would map to `127.0.0.1`).

## URL Parsing Bypass

### Understanding the Parser

The source code showed that URLs are parsed using `urlparse` from the `urllib.parse` library. I experimented with payloads from URL parsing discrepancy bypass techniques.

### Payload Evolution

**First attempt:**
```json
{"url":"http://127.0.0.1:1337\@scp-anomaly.com/vault?password=p4ssw0rdnya_H1b_Jay4_J4ya"}
```
This returned a bad request error.

![](<img/7.png>)

**Second attempt - Adding backslash:**
```json
{"url":"http://127.0.0.1:1337\\@scp-anomaly.com/vault?password=p4ssw0rdnya_H1b_Jay4_J4ya"}
```

![](<img/8.png>)

This successfully redirected to `127.0.0.1` but showed a 404 page instead of `/vault`. This happened because:
- `urlparse` doesn't treat `\` as a delimiter
- It splits the authority at the rightmost `@`, making the hostname `scp-anomaly.com`
- During the request, `urllib` normalizes `\` to `/`, making the authority boundary stop before the slash
- This redirects to `127.0.0.1:1337` while `@scp-anomaly.com/vault` becomes a path, causing 404

### Final Payload

![](<img/9.png>)

By adding `../` after `scp-anomaly.com`, the `/vault` endpoint became accessible. After dot-segment removal, it removes the previous path segment (`scp-anomaly.com`), allowing the `/vault` endpoint to combine with localhost.

**Final SSRF payload:**
```
http://127.0.0.1:1337\\@scp-anomaly.com/../vault?password=p4ssw0rdnya_H1b_Jay4_J4ya
```

This successfully retrieved the contents of `secret.txt`.

![](<img/10.png>)

## Secret Decoding

### Binary Analysis

![](<img/11.png>)

The contents of `secret.txt` were binary data. Using tools from dcode.fr:
1. Decoded the binary to reveal another encoding
2. Used cipher identifier from dcode.fr to determine the encoding type
3. After several decoding processes, discovered the secret: **`808-202-512-216`**

## Secret Console Access

### PIN Authentication

The source code revealed a `/secret-console` endpoint that requests a PIN from the user. Using the discovered secret (`808-202-512-216`), I gained access to the secret-console page.

## Remote Code Execution

### Console Analysis

The secret-console page contained a console that could execute user input. According to the source code, the console executes user input via `os.popen()`, allowing RCE with certain commands.

### File Discovery and Flag Extraction

![](<img/13.png>)

**Command:** `os.popen('ls -la')`
This displayed files in the current directory and revealed `r34l_fl4g.txt`.

![](<img/14.png>)

**Final command:** `os.popen('cat r34l_fl4g.txt')`
This retrieved the flag.

## Flag

```
HiB25{L00pB4ck_1ntrus10n_V1a_SSRF-Ng1nx_Byp4ss_Pwn3d_7125121ac}
```

## Summary

This challenge demonstrated a complex attack chain involving:

1. **Nginx ACL Bypass** - Using `\x85` character to bypass endpoint restrictions
2. **SSRF via URL Parsing Discrepancy** - Exploiting `urlparse` vs `urllib` behavior differences
3. **Localhost Access** - Bypassing IP restrictions through URL manipulation
4. **Multi-stage Decoding** - Binary and cipher decoding to reveal secrets
5. **Remote Code Execution** - Leveraging `os.popen()` for command execution

The vulnerability chain showcased how multiple security misconfigurations and parsing discrepancies can be chained together to achieve complete system compromise, from initial nginx bypass to final RCE.