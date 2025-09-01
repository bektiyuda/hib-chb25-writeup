# Format String Vulnerability Write-up

## Challenge Information

**Title:** Math   
**Description:** Very simple and fun mathematics. No attachment in this challenge.  
**Connection:** `nc m4.lu 69`

## Initial Analysis

### Network Connection Testing

First, I connected using `nc` and observed the prompt: `[1] 120*99 =`

When answering correctly or incorrectly, there was no change in behavior - the program simply echoed back the input: `"Your answer is (input)"`.

### Vulnerability Identification

This behavior provided a crucial clue that the program was executing `printf(buf)` without a safe format string. Since our input was being reflected directly, I suspected a **format string vulnerability**.

[](<img/1.png>)

If this assumption was correct, sending format specifiers like `%p`, `%x`, or `%s` should cause the program to read stack/memory contents and print them back.

## Exploitation Strategy

### Format String Testing

The target was to find the argument index on the stack that points to interesting strings (potentially containing the flag).

### Brute Force Approach

[](<img/2.png>)

I systematically brute-forced format string positions using `%$i$s` for `i=1` through `20` to dump different stack positions as strings.

**Payload pattern:** `%$1$s`, `%$2$s`, `%$3$s`, ..., `%$20$s`

### Successful Exploitation

[](<img/3.png>)

One of the format string positions successfully revealed the flag in the program's memory.

## Solution Process

1. **Connect to service:** `nc m4.lu 69`
2. **Identify vulnerability:** Notice input reflection suggests format string bug
3. **Test format strings:** Send various `%$i$s` payloads
4. **Memory dump:** Extract strings from different stack positions
5. **Flag discovery:** Find the position containing the flag

## Flag

```
HiB25{05058cf36cbe2063961a23e68fdf7c02}
```

## Summary

This challenge demonstrated:

1. **Vulnerability Recognition** - Identifying format string vulnerabilities through input reflection
2. **Format String Exploitation** - Using format specifiers to read arbitrary memory
3. **Stack Analysis** - Understanding how format strings access stack arguments
4. **Memory Exploration** - Systematically dumping memory contents to find sensitive data
5. **Remote Exploitation** - Exploiting vulnerabilities over network connections

The challenge showcased a classic format string vulnerability where unsafe use of `printf()` allows attackers to read arbitrary memory contents. By systematically probing different stack positions, the flag was discovered stored somewhere in the program's memory space.