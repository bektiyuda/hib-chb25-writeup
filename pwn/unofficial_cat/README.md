# Stack Buffer Overflow with Guard Variable Write-up

## Challenge Information

**Title:** Unofficial Cat  
**Description:** I made a website that reads a TXT file with cat, but I'm not sure if it's the official one.
**Connection:** https://unofficial-cat.ctf.m4.lu/

## Initial Analysis

### File Examination

The challenge provided several files:
- A binary file named `cat`
- A simple web application (`app.py`) that accepts file uploads and executes the binary against uploaded files
- A `flag.txt` file

### Binary Protection Analysis

![](<img/1.png>)

I performed basic analysis on the `cat` binary using `file` and `checksec` to identify active mitigation features:

- **No stack canary** - Stack overflow protection disabled
- **NX enabled** - Non-executable stack (code injection prevented)
- **PIE disabled** - Position Independent Executable not active (fixed addresses)

### Program Behavior Analysis

The `cat` program performs the following operations:

![](<img/2.png>)

1. Opens a file from command line arguments
2. Reads the file contents with an oversized read into a small local buffer (classic buffer overflow)
3. Prints the buffer contents
4. Checks a local stack variable (guard) to see if it equals `0xDEADBEEF`
5. If the guard matches, calls `execve("/bin/cat", ["cat","flag.txt"], NULL)` to print the flag

## Vulnerability Analysis

### Stack Buffer Overflow with Guard Variable

The vulnerability lies in the oversized read operation that overflows the local buffer and overwrites adjacent stack variables, including the guard variable. The program's logic creates a backdoor: if we can overwrite the guard with the magic value `0xDEADBEEF`, it will execute the real `/bin/cat` on `flag.txt`.

### Offset Calculation with GDB

To determine the exact offset needed to overwrite the guard variable:

![](<img/3.png>)

1. Created `cyclic.txt` containing output from `pwn cyclic 200`
2. Used GDB to set a breakpoint at `fgets`
3. Ran the program with `cyclic.txt` and used `finish` to return to main after buffer fill
4. Read 4 bytes at the guard location using `x/wx $rbp-0x4`
5. Got `0x61616174` which corresponds to "taaa" in the cyclic pattern
6. Found the position using `pwn cyclic -l taaa` which returned **76**

## Solution Implementation

### Payload Construction

The exploit requires:
- **76 bytes** of padding to reach the guard variable
- **4 bytes** containing `0xDEADBEEF` in little-endian format
- **Newline** to terminate the input

### Exploit Script

```python
with open("payload.txt", "wb") as f:
    f.write(b"A"*76 + (0xdeadbeef).to_bytes(4, "little") + b"\n")
print("payload.txt generated")
```

### Exploitation Process

1. **Generate payload:** Create `payload.txt` with precise offset and magic value
2. **Upload to web interface:** Submit the payload file through the web application
3. **Trigger execution:** The web app runs the vulnerable `cat` binary on our payload
4. **Guard check passes:** Our overwritten guard value matches `0xDEADBEEF`
5. **Flag retrieval:** Program executes `/bin/cat flag.txt` and returns the flag

![](<img/4.png>)

## Flag

```
HiB25{e1b9be5f736389faf8fb7d7be03c0da4}
```

## Summary

This challenge demonstrated:

1. **Classic Stack Buffer Overflow** - Exploiting oversized reads into fixed-size buffers
2. **Guard Variable Manipulation** - Overwriting stack variables to control program flow
3. **Web Application Integration** - Combining binary exploitation with web-based delivery
4. **Offset Calculation Techniques** - Using cyclic patterns and GDB for precise memory layout analysis

The challenge required understanding both the binary vulnerability and the web application's role in payload delivery. The key insight was recognizing that the "unofficial" cat binary contained a backdoor mechanism that could be triggered through careful stack manipulation. Rather than achieving code execution through traditional ROP chains, the solution exploited the program's own logic by satisfying its guard condition through buffer overflow.