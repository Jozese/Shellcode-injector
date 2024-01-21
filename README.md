# Shellcode injector
Basic shellcode injection into an existing process.

## Usage
```
	"Shellcode injector.exe" shellcodePath PID 
```
## Notes
If the provided shellcode is not valid shellcode, the created thread will crash, therefore, the entire targeted process might terminate.
