# SHA1 Hash Collision Authentication Bypass Write-up

## Challenge Information

**Title:** Dessert  
**Points:** 200  
**Author:** Yesver  
**Connection:** `nc ctf.m4.lu 65021`

## Description
As a closing challenge, here's some dessert for you! Congratulations for the consistency and determination throughout the process.

## Initial Analysis

### Service Examination

The challenge provides source code for the service running on `ctf.m4.lu:65021`. The critical component is the authentication mechanism implemented in the service.

### Authentication Logic Analysis

![](<img/1.png>)

The key function `unlock_dessert()` implements a unique authentication scheme with the following validation logic:

1. **String Inequality Check:** If `username == password`, returns permission error
2. **Hash Equality Check:** If `SHA1(username) != SHA1(password)`, returns permission error
3. **Success Condition:** Username and password must be different strings but have identical SHA1 hashes

This creates a logical contradiction that can only be satisfied through a **SHA1 hash collision**.

## Vulnerability Analysis

### Hash Collision Requirement

The authentication mechanism requires finding two different inputs that produce the same SHA1 hash output. This is known as a **hash collision** - a cryptographic scenario where:

```
Input1 ≠ Input2  AND  SHA1(Input1) = SHA1(Input2)
```

### SHA1 Collision Feasibility

While SHA1 collisions are theoretically difficult to generate, practical examples exist due to cryptographic research. The challenge hints at using known collision pairs rather than generating new ones.

## Solution Implementation

### Known SHA1 Collision Discovery

I located pre-computed SHA1 collision examples:

- **File 1:** https://arw.me/f/1.html
- **File 2:** https://arw.me/f/2.html

### Collision Verification

```bash
# Download the collision files
wget https://arw.me/f/1.html
wget https://arw.me/f/2.html

# Verify SHA1 collision
sha1sum 1.html 2.html
```

Both files produce identical SHA1 hashes despite having different content, confirming they form a valid collision pair.

![](<img/2.png>)

### Payload Extraction

To use these collision files as authentication credentials:

1. **Convert to hex representation:** Extract the hexadecimal representation of both files
2. **Use as credentials:** Submit one file's hex as username and the other's hex as password
3. **Satisfy both conditions:**
   - Username ≠ Password (different hex strings)
   - SHA1(username) = SHA1(password) (identical hash values)

### Exploitation Process

```python
# Pseudo-code for the exploitation process
with open('1.html', 'rb') as f1:
    file1_hex = f1.read().hex()

with open('2.html', 'rb') as f2:
    file2_hex = f2.read().hex()

# Use file1_hex as username and file2_hex as password
# Both will have the same SHA1 hash but different content
```

### Complete Attack Flow

1. **Download collision files:** Obtain the two SHA1 collision examples
2. **Extract hex values:** Convert both files to hexadecimal representation
3. **Connect to service:** Establish connection to `nc ctf.m4.lu 65021`
4. **Submit credentials:** Use one hex value as username, the other as password
5. **Bypass authentication:** The collision satisfies both validation requirements
6. **Retrieve flag:** Successfully unlock the dessert function

## Flag

```
HiB25{e7d1ffee5f15debe5462b46fc89d32fc}
```

## Summary

This challenge demonstrated:

1. **Hash Collision Exploitation** - Practical application of cryptographic hash collisions for authentication bypass
2. **SHA1 Vulnerabilities** - Understanding the security implications of collision-vulnerable hash functions
3. **Logic Contradiction Resolution** - Solving authentication puzzles through cryptographic properties
4. **Pre-computed Attack Resources** - Leveraging existing cryptographic research for practical exploitation

The challenge elegantly showcased how cryptographic weaknesses in hash functions can be exploited to bypass seemingly impossible authentication requirements. By requiring both string inequality and hash equality simultaneously, the challenge forced the use of hash collision techniques.

The key insight was recognizing that the authentication logic created a cryptographic puzzle that could only be solved through SHA1's known collision vulnerability. Rather than attempting to generate new collisions (computationally expensive), the solution leveraged existing collision pairs from cryptographic research, demonstrating how real-world attacks often build upon academic discoveries.

This "dessert" challenge served as an excellent conclusion, combining theoretical cryptographic concepts with practical exploitation techniques while celebrating the completion of the CTF journey.