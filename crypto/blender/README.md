# Manual Cryptanalysis and Pattern Recognition Write-up

## Challenge Information

**Title:** *dessert*  
**Points:** *200*  
**Author:** *Yesver*  

## Description
*As a closing challenge, here's some dessert for you! Congratulations for the consistency and determination throughout the process.
Author: Yesver
Connection Info
nc ctf.m4.lu 65021
*

## Initial Analysis

### Cipher Identification

![](<img/1.png>)

The challenge presented a long ciphertext without any hints about the encryption method used. The first step was identifying the cipher algorithm through automated analysis.

### Tool-Assisted Analysis

Using the cipher identification tool from `dcode.fr/cipher-identifier`, the analysis indicated that the highest probability cipher type was a **substitution cipher**. This suggested that each letter in the ciphertext corresponds to a specific letter in the plaintext through a consistent mapping.

## Cryptanalysis Approach

### Pattern Recognition Strategy

Substitution ciphers can be broken through frequency analysis and pattern recognition. The key is identifying recognizable patterns that correspond to known words or phrases in the target language.

### Initial Breakthrough - Date Pattern

![](<img/2.png>)

A critical breakthrough came from analyzing the pattern `'Ztot 3 Ymls 6569'`, which strongly resembled a date format. The structure suggested:
- `Ztot` → `Pada` (Indonesian: "On")
- `3` → `3` (number remains unchanged initially)  
- `Ymls` → `Juli` (Indonesian: "July")
- `6569` → A year (likely `2025` based on context)

This provided the initial character mappings:
- Z → P
- t → a  
- o → d
- Y → J
- M → u
- l → l
- s → i

### Progressive Pattern Analysis

#### Repeated Letter Patterns

![](<img/3.png>)

The three-letter sequence `"GPG"` appearing after numbers suggested the Indonesian abbreviation `"SKS"` (Satuan Kredit Semester - Credit Units). This provided:
- G → S
- P → K

#### Word Structure Analysis

![](<img/4.png>)

With the initial mappings established, other words became recognizable, allowing for progressive decryption:
- `KULIAJ` → `KULIAH` (J → H)
- `AKADEXIK` → `AKADEMIK` (X → M)  
- `DIJELASKAF` → `DIJELASKAN` (F → N)
- `SQSIALISASI` → `SOSIALISASI` (Q → O)
- `JADCAL` → `JADWAL` (C → W)
- `DAPAK` → `DAPAT` (K → T)

### Complete Alphabet Mapping

Through systematic analysis of word patterns and contextual clues, a complete substitution mapping was established for all alphabetic characters.

## Numeric Cipher Analysis

### Hypothesis Formation

![](<img/5.png>)

The numeric substitution required separate analysis. Key patterns observed:
- `6569` → `2025` (contemporary year)
- `729 SKS` → `145 SKS` (credit unit format)
- `770 SKS` → `118 SKS` (credit unit format)  
- `8,9 - 1 Tahun` → `3,5 - 7 Tahun` (time range format)
- `PKL (2 SKS)` → `PKL (4 SKS)` (internship credits)
- `745 SKS` → `160 SKS` (total credits)

### Numeric Mapping Derivation

Based on the pattern analysis, the numeric substitution mapping was determined:
- 6 → 2
- 9 → 5  
- 0 → 8
- 7 → 1
- 8 → 3
- 1 → 7
- 2 → 4
- 4 → 6
- 3 → 9

## Solution Implementation

### Decryption Process

1. **Apply character substitution** using the derived alphabetic mapping
2. **Apply numeric substitution** using the derived numeric mapping  
3. **Format flag** by converting to lowercase as required
4. **Verify context** against the reference document about academic program coordination

### Context Verification

The decrypted text revealed content about academic program coordination at Universitas Brawijaya's Computer Science Faculty, specifically regarding course planning for the odd semester of academic year 2025/2026. This provided validation that the substitution mappings were correct.

### Flag Extraction

After applying both alphabetic and numeric substitutions and converting to the required lowercase format, the flag was successfully extracted.

## Flag

```
HiB25{25d474f7c45d63b3678d9e5e363ec08e}
```

## Summary

This challenge demonstrated:

1. **Cipher Identification** - Using automated tools to determine the encryption method
2. **Pattern Recognition** - Identifying structural patterns like dates and abbreviations  
3. **Progressive Cryptanalysis** - Building upon initial discoveries to expand the substitution key
4. **Contextual Analysis** - Using domain knowledge to validate and guide decryption attempts
5. **Dual Substitution Systems** - Handling separate mappings for alphabetic and numeric characters

The key insight was recognizing that contextual patterns (dates, academic terminology, numerical formats) could provide the breakthrough needed to establish initial character mappings. From there, systematic analysis of word structures allowed for complete reconstruction of both alphabetic and numeric substitution keys.

The challenge highlighted the importance of domain knowledge in cryptanalysis - understanding Indonesian academic terminology and date formats was crucial for identifying the correct patterns and validating the decryption results.