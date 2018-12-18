unformbook.py
===

Python script that helps extracting C2 configured on a FormBook malware sample.

Example of use:

```
$ python unformbook.py payload.exe 
[+] MASM detected. Version 10.00.40219. FormBook candidate. Continue...
[+] Number of encbuffers is ok. Continue...
[+] C&C URI found: hxxp://www.blandeglos.com/sh/
```

Based on work made by [@tildedennis](https://github.com/tildedennis) and [@ThisIsSecurity](https://github.com/ThisIsSecurity)
