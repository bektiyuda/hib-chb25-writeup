import base64

pdf_content = base64.b64decode("<base64_response>")
with open('output.pdf', 'wb') as f:
    f.write(pdf_content)
print("PDF saved as output.pdf")
