# Golang Binary Static Analysis Write-up

## Challenge Information

**Title:** gogogo  
**Description:** gogogo

## Initial Analysis

### File Identification

[](<img/1.png>)

Using the `file` command revealed that this is an ELF 64-bit binary that is statically linked and built with Go (evidenced by the Go BuildID). This provided important clues:
- Symbols might be minimal due to static linking
- Constant assets are often "embedded" in the `.rodata` section

### Runtime Behavior

[](<img/2.png>)

Running the binary directly only prompted for input and exited without producing any output. This indicated:
- No visible verification/print paths
- The flag is likely stored passively in the data segment rather than being dynamically generated

## Static Analysis Approach

### Go Binary Analysis

[](<img/3.png>)

With static Go binaries, `go tool objdump -s main.main gogogo` provided some insight. The main function appeared to only read from stdin (similar to `fmt.Fscan` / `bufio` call patterns) without validation logic leading to flag printing.

This strengthened the hypothesis that the flag is "embedded" as a constant rather than computed or validated.

### Data Segment Scanning

Since the flag appeared to be embedded as a constant, I performed a comprehensive scan to find long sequences matching the pattern of "printable ASCII" + `\x00\x00` repeating.

## Solution Implementation

### Flag Extraction Script

```python
import sys

path = 'gogogo'
data = open(path, 'rb').read()

best_start = best_run = 0
i, n = 0, len(data)

# Find longest run of (printable\x00\x00) repeating pattern
while i < n - 24:  # minimum 8*3 bytes
    s, run = i, 0
    while i + 2 < n and 32 <= data[i] <= 126 and data[i+1] == 0 and data[i+2] == 0:
        run += 1
        i += 3
    if run > best_run:
        best_run, best_start = run, s
    i = s + 1 if run == 0 else i

if best_run == 0:
    sys.exit("pattern not found")

# Extract core string by taking every 3rd byte (the printable characters)
core = data[best_start:best_start + 3*best_run:3].decode('ascii', 'ignore')

# Check for trailing '}' character
tail = data[best_start + 3*best_run: best_start + 3*best_run + 1]
if tail == b'}' and not core.endswith('}'):
    core += '}'

print(core)
```

### Algorithm Explanation

The script works by:

1. **Pattern Recognition:** Looking for sequences where printable ASCII characters are followed by two null bytes (`\x00\x00`)
2. **Run Detection:** Finding the longest consecutive sequence of this pattern
3. **Character Extraction:** Taking every 3rd byte (the printable characters) while skipping the null bytes
4. **Boundary Handling:** Checking for a trailing `}` character that might not follow the null-byte pattern

## Key Insights

### Go String Encoding

In Go binaries, strings are often stored with specific padding or encoding patterns. The pattern `printable_char\x00\x00` suggests the flag was embedded in a way that creates this distinctive memory layout.

### Static Analysis Strategy

Rather than trying to understand the complex Go runtime and execution flow, the solution focused on:
- Recognizing that flags are typically embedded as constants
- Identifying distinctive memory patterns in Go binaries
- Extracting data based on structural patterns rather than execution flow

## Flag

```
HiB25{G0_G0_P0W3R_R4NG3RS}
```

## Summary

This challenge demonstrated:

1. **Go Binary Analysis** - Understanding statically linked Go executables
2. **Data Segment Mining** - Scanning for embedded constants and strings
3. **Pattern Recognition** - Identifying distinctive memory layouts in compiled binaries
4. **Static Extraction** - Retrieving flags without dynamic analysis or execution
5. **Encoding Understanding** - Recognizing Go's string storage patterns

The solution showcased that sometimes the most efficient approach to reverse engineering is not to understand the program's logic, but to recognize how data is stored and structured in the compiled binary. The flag name `HiB25{G0_G0_P0W3R_R4NG3RS}` playfully references both the Go programming language and the Power Rangers, fitting the challenge's theme.