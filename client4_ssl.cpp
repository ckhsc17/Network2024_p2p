// Total time: 9.0 hours
// 11/15 11:50 - 11/15 15:50
// 11/16 11:50 - 11/16 13:10
// 11/16 22:40 - 11/16 02:00

#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <thread>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <filesystem>
#include <cstdlib>

#include <mutex>

#define MAX_TRANSFER_AMOUNT 10000

using namespace std;

// Mutex to protect shared resources like account balance and online list
std::mutex mtx;

void p2pListener(int port, int clientSocket, const string& username); //const string& username //const void* username
bool findUserAccountDetails(const string& buffer, const string& targetUserAccount, string& payeeIp, string& payeePortNum, int& balance);
std::string encryptMessageWithPublicKey(const std::string& message, const std::string& publicKeyFile, bool isClient = true);
std::string decryptMessageWithPrivateKey(const std::string& encryptedMessage, const std::string& privateKeyFile);


void p2pListener(int port, int clientSocket, const string& username) {  
    //const char* userCStr = static_cast<const char*>(username);
    //std::string userStr(userCStr);
    
    // 作為 P2P listener的socket (client server)
    int transferSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (transferSocket == -1) {
        cerr << "Socket creation failed!" << endl;
        return;
    }

    struct sockaddr_in serverInfo,clientInfo;
    socklen_t addrlen = sizeof(clientInfo);
    bzero(&serverInfo,sizeof(serverInfo));

    serverInfo.sin_family = AF_INET;
    //serverInfo.sin_addr.s_addr = inet_addr("127.0.0.1"); //INADDR_ANY vs. 127.0.0.1(本機測試)

    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(port);

    bind(transferSocket, (struct sockaddr *)&serverInfo, sizeof(serverInfo));
    listen(transferSocket, 5);

    cout << "P2P listener started on port " << port << endl;

    while (1) {
        cout << "Enter command:\n1: Register\n2: Login\n3: List\n4: Transfer\n5: Exit" << endl;
        int payer = accept(transferSocket,(struct sockaddr*) &clientInfo, &addrlen);
        if (payer != -1) {
            std::lock_guard<std::mutex> lock(mtx);
            // Handle incoming message from another client
            cout << "Connected to payer!" << endl;
            printf("payer IP: %s\n", inet_ntoa(clientInfo.sin_addr)); //clientInfo的用處

            
            char p2p_buffer[10000] = {0}; //需要先清空buffer //在這裡定義東西會不會有問題？因為這個buffer是要在while loop裡面用的
            cout << "initial: " << p2p_buffer << endl;
            int bytesReceived = recv(payer, p2p_buffer, sizeof(p2p_buffer), 0); //不保證一次收完
            cout << "bytesReceived: " << bytesReceived << endl;
            cout << "p2p_buffer before: " << p2p_buffer << endl;
            p2p_buffer[bytesReceived] = '\0';
            cout << "p2p_buffer after: " << p2p_buffer << endl;
            

            /*
            char p2p_buffer[10000] = {0}; // 初始化 buffer
            int totalBytesReceived = 0;
            int bytesReceived = 0;

            // 循環接收數據
            while ((bytesReceived = recv(payer, p2p_buffer + totalBytesReceived, sizeof(p2p_buffer) - totalBytesReceived, 0)) > 0) {
                cout << "receiving..." << endl;
                totalBytesReceived += bytesReceived;
                if (totalBytesReceived >= sizeof(p2p_buffer)) {
                    std::cerr << "Buffer overflow, received too much data!" << std::endl;
                    break;
                }
            }

            // 結束符
            if (totalBytesReceived > 0) {
                p2p_buffer[totalBytesReceived] = '\0';
                std::cout << "Total bytes received: " << totalBytesReceived << std::endl;
                std::cout << "p2p_buffer: ";
                for (int i = 0; i < totalBytesReceived; ++i) {
                    std::cout << std::hex << static_cast<int>(p2p_buffer[i]) << " ";
                }
                std::cout << std::dec << std::endl;
            } else {
                std::cerr << "Failed to receive data or connection closed." << std::endl;
            }
            */

            //string receivedMessage(p2p_buffer); //###
            string receivedMessage(p2p_buffer, bytesReceived);

            /*
            std::vector<unsigned char> buffer(2500);
            int bytesReceived = recv(payer, buffer.data(), buffer.size(), 0);
            buffer.resize(bytesReceived);  // Resize vector to the actual received size
            cout << "buffer size: " << buffer.size() << endl;
            */
            cout << "Received message: " << receivedMessage << endl; //加密後的訊息

            /*
            char buffer[2500];
            int bytesReceived = recv(payer, buffer, sizeof(buffer), 0);
            buffer[bytesReceived] = '\0';
            
            //char buffer[1024] = {};
            //read(payer, buffer, sizeof(buffer));
            cout << "Received message: " << buffer << endl; //加密後的訊息
            */

            // Payee decrypts the message with their private key
            cout << "private key file: " << username + "_private.pem" << endl;
            std::string decryptedMessage = decryptMessageWithPrivateKey(receivedMessage, username + "_private.pem"); // username + "_private.pem"
            std::cout << "Decrypted Message on Payee: " << decryptedMessage << std::endl;

            //funtion to read server's public key
            send(clientSocket, "List", 4, 0);

            memset(p2p_buffer, 0, sizeof(p2p_buffer)); //清空buffer
            // Receive server response (單獨處理）
            bytesReceived = recv(clientSocket, p2p_buffer, sizeof(p2p_buffer), 0);
            p2p_buffer[bytesReceived] = '\0';
            string server_response(p2p_buffer, bytesReceived);
            
            /*
            // Find the server's public key in the buffer
            size_t firstNewline = server_response.find('\n');
            size_t secondNewline = server_response.find('\n', firstNewline + 1);
            string serverPublicKey;
            serverPublicKey = server_response.substr(firstNewline + 1, secondNewline - firstNewline - 1);
            cout << "Server Public Key: " << serverPublicKey << endl;
            */

            // Find the server's public key in the buffer
            // Find the position of the BEGIN and END markers
            size_t beginPos = server_response.find("-----BEGIN PUBLIC KEY-----");
            size_t endPos = server_response.find("-----END PUBLIC KEY-----");
            string serverPublicKey;
            // If both markers are found
            if (beginPos != std::string::npos && endPos != std::string::npos) {
                // Extract the public key substring (start right after "-----BEGIN PUBLIC KEY-----" and go till before "-----END PUBLIC KEY-----")
                serverPublicKey = server_response.substr(beginPos + 27, endPos - beginPos - 27); // 27 is the length of "-----BEGIN PUBLIC KEY-----"

                // Optional: Remove newlines or extra spaces in the public key part
                // Here we can remove any unnecessary whitespace or newline characters
                serverPublicKey.erase(remove(serverPublicKey.begin(), serverPublicKey.end(), '\n'), serverPublicKey.end());
                serverPublicKey.erase(remove(serverPublicKey.begin(), serverPublicKey.end(), '\r'), serverPublicKey.end());

                // Print the extracted public key (or handle it as needed)
                std::cout << "Extracted Public Key: " << std::endl << serverPublicKey << std::endl;
            } else {
                std::cout << "Public key not found!" << std::endl;
            }

            /*
            if (server_response.find("Server Public Key") != std::string::npos) {
                serverPublicKey = server_response.substr(firstNewline + 1, secondNewline - firstNewline - 1);
                cout << "Server Public Key: " << serverPublicKey << endl;
            } else {
                cout << "Server Public Key not found!" << endl;
            }
            */
            /*
            // 找到第一个换行符的位置
            size_t firstNewline = server_response.find("\r\n");
            if (firstNewline == std::string::npos) {
                std::cout << "Error: No CRLF found!" << std::endl;
                return 1;
            }

            // 找到第二个换行符的位置
            size_t secondNewline = server_response.find("\r\n", firstNewline + 2);
            if (secondNewline == std::string::npos) {
                std::cout << "Error: No second CRLF found!" << std::endl;
                return 1;
            }

            // 提取第二行，即Server Public Key
            std::string serverPublicKey = server_response.substr(firstNewline + 2, secondNewline - firstNewline - 2);
            
            std::cout << "Server Public Key: " << serverPublicKey << std::endl;

            return 0;
            */

            // Payee re-encrypts the verified message for the server
            std::string encryptedForServer = "TRANSFER#";
            //encryptedForServer += encryptMessageWithPublicKey(decryptedMessage, "server_public.pem"); //這裡要改成從List中找到的server的public key而非直接指定.pem檔
            encryptedForServer += encryptMessageWithPublicKey(decryptedMessage, serverPublicKey, false); // server_public.pem

            cout << "Confirm the amount and inform the server to update the balance." << endl;
            // Extract the payer's username, amount, and payee's username
            // Client B (payee) 確認轉帳金額格式之後回傳給server更新餘額
            send(clientSocket, encryptedForServer.c_str(), encryptedForServer.size(), 0);
            cout << "Payee sent transfer message to server." << endl;

            memset(p2p_buffer, 0, sizeof(p2p_buffer)); //清空buffer
            bytesReceived = recv(clientSocket, p2p_buffer, sizeof(p2p_buffer), 0);
            p2p_buffer[bytesReceived] = '\0';
            cout << "transfer outcome: " << p2p_buffer << endl;
            cout << "Successfully received message from server." << endl;

            close(payer);
        }
        else {
            cout << "outside Connection detected but failed!" << endl;
        }
    }

    close(transferSocket); //寫一個logout的function?
}

void printLastError() {
    unsigned long errCode = ERR_get_error();  // Get the error code
    if (errCode) {
        char errMsg[120];  // Buffer to hold the error message
        ERR_error_string_n(errCode, errMsg, sizeof(errMsg));  // Convert error code to string
        std::cerr << "OpenSSL error: " << errMsg << std::endl;
    } else {
        std::cerr << "No OpenSSL error" << std::endl;
    }
}

bool findUserAccountDetails(const string& buffer, const string& targetUserAccount, string& payeeIp, string& payeePortNum, int& balance) {
    // Construct the regex pattern for the target account format "<targetUserAccount>#<IPaddr>#<portNum>"
    //regex pattern(R"(([^#]+)#(\d+)#([^#]+))");
    //string pattern = targetUserAccount + R"(#([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})#(\d+))";
    string pattern = targetUserAccount + "#([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})#(\\d+)";

    
    size_t delimiter = buffer.find("\n");
    balance = stoi(buffer.substr(0, delimiter));
    cout << "Balance: " << balance << endl;
    
    // Create the regex with the pattern
    regex accountRegex(pattern);
    smatch match;

    // Search for the target account in the buffer
    if (regex_search(buffer, match, accountRegex)) {
        // Extract IP and port from the match
        payeeIp = match[1].str();
        payeePortNum = match[2].str();

        cout << "Target User Account Found!" << endl;
        cout << "IP Address: " << payeeIp << endl;
        cout << "Port Number: " << payeePortNum << endl;
        return true;
    } else {
        cout << "Target User Account not found in the list." << endl;
        return false;
    }
}

void generateClientKeys(const std::string& clientPrivateKey, const std::string& clientPublicKey) {
    if (!std::filesystem::exists(clientPrivateKey) || !std::filesystem::exists(clientPublicKey)) {
        std::cout << "Generating Client keys...\n";
        
        // Generate private key
        std::string generatePrivateKeyCmd = "openssl genpkey -algorithm RSA -out " + clientPrivateKey + " -pkeyopt rsa_keygen_bits:2048";
        std::system(generatePrivateKeyCmd.c_str());
        
        // Generate public key from private key
        std::string generatePublicKeyCmd = "openssl rsa -pubout -in " + clientPrivateKey + " -out " + clientPublicKey;
        std::system(generatePublicKeyCmd.c_str());

        std::cout << "Client keys generated.\n";
    } else {
        std::cout << "Client keys already exist.\n";
    }
}

//有可能有兩種情境：ClientA加密給ClientB、ClientB加密給Server
std::string encryptMessageWithPublicKey(const std::string& message, const std::string& publicKeyFile, bool isClient) {
    RSA* rsa;
    if (isClient) {
        cout << "encrypt with client public key" << endl;
        cout << "publicKeyFile: " << publicKeyFile << endl;
        FILE* pubKeyFile = fopen(publicKeyFile.c_str(), "rb");
        cout << "pubKeyFile: " << pubKeyFile << endl;
        if (!pubKeyFile) {
            std::cerr << "Failed to open public key file" << std::endl;
            return "";
        }
        
        //0xffffa80520d0
        //0xaaaad4ea8350
        rsa = PEM_read_RSA_PUBKEY(pubKeyFile, NULL, NULL, NULL);
        fclose(pubKeyFile);

        if (!rsa) {
            std::cerr << "Failed to read public key" << std::endl;
            return "";
        }
    } else {
        cout << "encrypt with server public key" << endl;
        // If publicKeyFile is a string containing the public key (PEM format)
        cout << "publicKeyFile: " << publicKeyFile << endl;
        string public_key = "-----BEGIN PUBLIC KEY-----\n";
        public_key += publicKeyFile;
        public_key += "\n-----END PUBLIC KEY-----\n";
        BIO* bio = BIO_new_mem_buf(public_key.data(), public_key.size());
        if (!bio) {
            std::cerr << "Failed to create BIO from string" << std::endl;
            return "";
        }

        cout << "bio: " << bio << endl;

        rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if (!rsa) {
            std::cerr << "Failed to read public key from string" << std::endl;
            printLastError();  // Print the error if the reading failed
            return "";
        }
    }
    

    int rsaLen = RSA_size(rsa);
    unsigned char* encrypted = new unsigned char[rsaLen];

    int result = RSA_public_encrypt(message.size(), (unsigned char*)message.c_str(), encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);

    if (result == -1) {
        std::cerr << "Encryption failed" << std::endl;
        ERR_print_errors_fp(stderr);
        delete[] encrypted;
        return "";
    }

    std::string encryptedMessage((char*)encrypted, result);
    delete[] encrypted;
    cout << "Payer encrypt success!" << endl;
    return encryptedMessage;
}

std::string decryptMessageWithPrivateKey(const std::string& encryptedMessage, const std::string& privateKeyFile) {
    FILE* privKeyFile = fopen(privateKeyFile.c_str(), "rb");
    if (!privKeyFile) {
        std::cerr << "Failed to open private key file" << std::endl;
        return "";
    }

    RSA* rsa = PEM_read_RSAPrivateKey(privKeyFile, NULL, NULL, NULL);
    fclose(privKeyFile);

    if (!rsa) {
        std::cerr << "Failed to read private key" << std::endl;
        return "";
    }
    cout << "private key read success!" << endl;

    int rsaLen = RSA_size(rsa);
    unsigned char* decrypted = new unsigned char[rsaLen]; //###

    int result = RSA_private_decrypt(encryptedMessage.size(), (unsigned char*)encryptedMessage.c_str(), decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);

    if (result == -1) {
        std::cerr << "Decryption failed" << std::endl;
        ERR_print_errors_fp(stderr);
        delete[] decrypted;
        return "";
    }

    std::string decryptedMessage((char*)decrypted, result);
    delete[] decrypted;
    cout << "Payee decrypt success!" << endl;
    return decryptedMessage;
}

/*
void findSelfAccountDetails(const string& buffer, const string& targetUserAccount, string& payeeIp, string& payeePortNum) {
    // Construct the regex pattern for the target account format "<targetUserAccount>#<IPaddr>#<portNum>"
    //regex pattern(R"(([^#]+)#(\d+)#([^#]+))");
    //string pattern = targetUserAccount + R"(#([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})#(\d+))";
    string pattern = targetUserAccount + "#([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})#(\\d+)";

    
    // Create the regex with the pattern
    regex accountRegex(pattern);
    smatch match;

    // Search for the target account in the buffer
    if (regex_search(buffer, match, accountRegex)) {
        // Extract IP and port from the match
        payeeIp = match[1].str();
        payeePortNum = match[2].str();

        cout << "Target User Account Found!" << endl;
        cout << "IP Address: " << payeeIp << endl;
        cout << "Port Number: " << payeePortNum << endl;
    } else {
        cout << "Target User Account not found in the list." << endl;
    }
}
*/

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <server_ip> <server_port>" << endl;
        return 1;
    }
    cout << "hi" << endl;
    const char *serverIp = argv[1];  // 取得 IP 地址
    int serverPort = stoi(argv[2]);  // 取得端口並轉換為整數
    cout << "Connecting to server " << serverIp << ":" << serverPort << endl;

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        cerr << "Socket creation failed!" << endl;
        return 0;
    }



    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    serverAddr.sin_addr.s_addr = inet_addr(serverIp);

    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
        cerr << "Connection failed!" << endl;
        close(clientSocket);
        return 0;
    }
    cout << "Connected to server." << endl;

    string username;
    int balance = 0, bytesReceived = 0;
    while (true) {
        // Enter command
        cout << "Enter command:\n1: Register\n2: Login\n3: List\n4: Transfer\n5: Exit" << endl;
        string message;
        cin >> message;
        //getline(cin, message);
        //cin.ignore();
        //cout << "Sending message to server: " << message << endl;

        
        char buffer[1024] = {0};

        // Register 
        if (message == "1") {
            string registerMessage;
            cout << endl << "Enter your username: ";
            cin >> username;
            // Check if the username contains any special characters or restricted words
            if (username.find("#") != string::npos || username.find("List") != string::npos || username.find("List") != string::npos) {
                cerr << "Invalid username. It cannot contain '#' or be 'List' or 'Exit'. Please try again." << endl;
                continue; // Skip this iteration and ask for input again
            }
            registerMessage = "REGISTER#" + username;

            send(clientSocket, registerMessage.c_str(), registerMessage.length(), 0);
            cout << "Successfully sent register message to server." << endl;

            memset(buffer, 0, sizeof(buffer)); //清空buffer
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            buffer[bytesReceived] = '\0';
            string receivedMessage(buffer); //便於後面的比較
            if (receivedMessage.find("100 OK") != std::string::npos) {
                cout << "Register success." << endl;
                // Define key paths for Client A (modify if needed for other clients)
                std::string clientPrivateKey = username + "_private.pem";
                std::string clientPublicKey = username + "_public.pem";
                cout << "generating keys..." << endl;
                // Generate keys if they do not exist
                generateClientKeys(clientPrivateKey, clientPublicKey);
            }
            else if (receivedMessage.find("210 FAIL") != std::string::npos) {
                cerr << "Register fail. User already exists." << endl;
            }
            else {
                cout << "server response: " << receivedMessage << endl; //ex. 230 Input format error
            }
        }

        // Login
        else if (message == "2") {
            string loginMessage, portNum;
            //int portNum;
            cout << endl << "Enter your username: ";
            cin >> username;
            // Check if the username contains any special characters or restricted words
            if (username.find("#") != string::npos || username.find("List") != string::npos || username.find("List") != string::npos) {
                cerr << "Invalid username. It cannot contain '#' or be 'List' or 'Exit'. Please try again." << endl;
                continue; // Skip this iteration and ask for input again
            }
            cout << endl << "Enter your port number: ";
            cin >> portNum;
            // Check if the port number is valid？
            loginMessage = username + "#" + portNum;

            send(clientSocket, loginMessage.c_str(), loginMessage.length(), 0);
            cout << "Successfully sent login message to server." << endl;

            memset(buffer, 0, sizeof(buffer)); //清空buffer
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            buffer[bytesReceived] = '\0';
            string receivedMessage(buffer); //便於後面的比較
            if (receivedMessage.find("220 AUTH_FAIL") != std::string::npos) {
                cerr << "Authentication failed, not registered!" << endl;
            }  
            else {
                cout << "server response: \n" << receivedMessage << endl; //有空可以處理後再給client看
                // Start P2P listener thread on port 8701
                int loginPortNum = stoi(portNum);
                //thread p2pThread(p2pListener, loginPortNum, clientSocket, std::ref(username));  
                std::thread p2pThread(p2pListener, loginPortNum, clientSocket, username); //static_cast<const void*>(username.c_str())
                p2pThread.detach(); //detach thread，不用等待thread結束而是在背景執行
            }
        }

        // List
        else if (message == "3") {
            send(clientSocket, "List", 4, 0);
            cout << "Successfully sent List message to server." << endl;
            // Receive server response (單獨處理）
            memset(buffer, 0, sizeof(buffer)); //清空buffer
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            buffer[bytesReceived] = '\0';
            cout << buffer << endl;
            cout << "Successfully received message from server." << endl;
        }

        // Transfer
        else if (message == "4") {
            string payee, amount, payeeIp, payeePortNum;
            cout << endl << "Enter the payee's username: ";
            cin >> payee;
            cout << endl << "Enter the amount to transfer: ";
            cin >> amount;

            send(clientSocket, "List", 4, 0);

            memset(buffer, 0, sizeof(buffer)); //清空buffer
            // Receive server response (單獨處理）
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            buffer[bytesReceived] = '\0';
            cout << "Successfully received message from server." << endl;

            // Find the payee's account details in the buffer
            if (!(findUserAccountDetails(buffer, payee, payeeIp, payeePortNum, balance))){
                cerr << "Payee not found. Please try again." << endl;
                continue;
            }
            if (balance < stoi(amount)) {
                cerr << "Insufficient balance. Please try again." << endl;
                continue;
            }
            if (stoi(amount) > MAX_TRANSFER_AMOUNT) {
                cerr << "Transfer amount exceeds the maximum limit. Please try again." << endl;
                continue;
            }

            //cout << "hi payeeIp: " << payeeIp << endl;
            //cout << "hi payeePortNum: " << payeePortNum << endl;

            // Connect to a P2P listener on the payee's side and send the transfer message
            int payeeClientSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (payeeClientSocket == -1) {
                cerr << "Socket creation failed!" << endl;
                return 0;
            }

            sockaddr_in payeeAddr;
            payeeAddr.sin_family = AF_INET;
            payeeAddr.sin_port = htons(stoi(payeePortNum));
            payeeAddr.sin_addr.s_addr = inet_addr(payeeIp.c_str());
            //payeeAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //先做本地測試


            if (connect(payeeClientSocket, (struct sockaddr *)&payeeAddr, sizeof(payeeAddr)) == -1) {
                cerr << "Connection failed!" << endl;
                close(payeeClientSocket);
                return 0;
            }
            cout << "Connected to payee listener." << endl;

            std::lock_guard<std::mutex> lock(mtx);
            string transferMessage = username + "#" + amount + "#" + payee;
            cout << "username: " << username << endl;
            cout << "Transfer message: " << transferMessage << endl;

            std::string encryptedMessage = encryptMessageWithPublicKey(transferMessage, payee + "_public.pem");
            cout << "Encrypted Message length: " << encryptedMessage.length() << endl;
            cout << "Encrypted Message: " << encryptedMessage << endl;
            send(payeeClientSocket, encryptedMessage.c_str(), encryptedMessage.length(), 0); //傳送加密訊息給payee
            cout << "Successfully sent encrypted transfer message to payee." << endl;

            //regex pattern(R"(([^#]+)#(\d+)#([^#]+))");
        }

        else if (message == "5") {
            send(clientSocket, "Exit", 4, 0);
            cout << "Successfully sent Exit message to server." << endl;
            memset(buffer, 0, sizeof(buffer)); //清空buffer
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            buffer[bytesReceived] = '\0';
            string message(buffer);
            if (message.find("Bye") != std::string::npos) {
                cout << "Exit success." << endl;
            }
            else {
                cout << "server response: " << buffer << endl; //ex. 230 Input format error
            }
            close(clientSocket);
            break;
        }

        else {
            cout << "Invalid command. Please try again." << endl;
            continue;
        }

    }

    return 0;
}

/*
        // Register (或許有助於激發安全傳輸方面的靈感)
        if (message == "Register") {
            string registerMessage;
            cout << "Enter your username: ";
            cin >> registerMessage;
            cout << "Enter your password: ";
            cin >> registerMessage;
            cout << "Enter your initial balance: ";
            cin >> registerMessage;
            cout << "Enter your public key: ";
            cin >> registerMessage;

            send(clientSocket, registerMessage.c_str(), registerMessage.length(), 0);
            cout << "Successfully sent register message to server." << endl;
        }
*/