// Total time: 9.0 hours
// 11/15 11:50 - 11/15 15:50
// 11/16 11:50 - 11/16 13:10
// 11/16 22:40 - 11/16 02:00


#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <algorithm>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstdlib>

#define MAX_CLIENTS 10

using namespace std;

// Mutex to protect shared resources like account balance and online list
std::mutex mtx;

// Structure to store account data
struct Account {
    std::string accountName;
    double balance; // Initial balance is 10000
    std::string ipAddress;
    int portNum;

    // Constructor with a default value for balance
    Account(const std::string& name, double initialBalance = 10000, 
            const std::string& ip = "127.0.0.1", int port = 0)
        : accountName(name), balance(initialBalance), ipAddress(ip), portNum(port) {}
    // Define equality operator
    bool operator==(const Account& other) const {
        return accountName == other.accountName;
    }
};

std::vector<Account> accountsOnline;
std::vector<std::thread> workerThreads;

enum LogLevel {
    LOG_NONE,  // No log
    LOG_SIMPLE, // Simple logs (register, login, exit)
    LOG_STATUS, // Status logs (including online list)
    LOG_ALL // All logs (including message transmission)
};

// Global variable to store the selected log level
LogLevel logLevel = LOG_NONE;

// Function declarations
void handleClient(int clientSocket, const std::string& public_key = "");
void registerClient(int clientSocket, const std::string& userName);
void loginClient(int clientSocket, const std::string& userName, int port, const std::string& public_key);
void sendOnlineList(int clientSocket, const std::string& userName = "", const std::string& public_key = "");
void processTransaction(int clientSocket, const std::string& fromUser, const std::string& toUser, double amount);
void sendResponse(int clientSocket, const std::string& message);
void clientExit(int clientSocket);
void logMessage(const std::string& message, LogLevel level);
void workerThreadFunction(int clientSocket, const std::string& public_key);

void generateServerKeys(const std::string& serverPrivateKey, const std::string& serverPublicKey) {
    if (!std::filesystem::exists(serverPrivateKey) || !std::filesystem::exists(serverPublicKey)) {
        std::cout << "Generating Server keys...\n";
        
        // Generate private key
        std::string generatePrivateKeyCmd = "openssl genpkey -algorithm RSA -out " + serverPrivateKey + " -pkeyopt rsa_keygen_bits:2048";
        std::system(generatePrivateKeyCmd.c_str());

        // Generate public key from private key
        std::string generatePublicKeyCmd = "openssl rsa -pubout -in " + serverPrivateKey + " -out " + serverPublicKey;
        std::system(generatePublicKeyCmd.c_str());

        std::cout << "Server keys generated.\n";
    } else {
        std::cout << "Server keys already exist.\n";
    }
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
    unsigned char* decrypted = new unsigned char[rsaLen];

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

std::string readPemFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return "";
    }

    // Read the entire file content into a string
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    return buffer.str();  // Return the content as a string
}

std::string getClientIp(int clientSocket) {
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    char ip[INET_ADDRSTRLEN]; // IPv4 地址的最大長度

    if (getpeername(clientSocket, (struct sockaddr*)&addr, &addrLen) == -1) {
        perror("getpeername failed");
        return "Unknown"; // 如果獲取失敗，返回 "Unknown"
    }

    if (inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip)) == nullptr) {
        perror("inet_ntop failed");
        return "Unknown"; // 如果轉換失敗，返回 "Unknown"
    }

    return std::string(ip);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <portNum> <Option>" << std::endl;
        return 1;
    }

    int port = std::stoi(argv[1]); //這裡可以做更多的檢查
    if (port < 1024 || port > 65535) {
        std::cerr << "Port must be in the range 1024 to 65535!" << std::endl;
        return 1;
    }

    // Set log level based on the provided option
    std::string option = argv[2];
    if (option == "-d") {
        logLevel = LOG_SIMPLE;
    } else if (option == "-s") {
        logLevel = LOG_STATUS;
    } else if (option == "-a") {
        logLevel = LOG_ALL;
    } else {
        std::cerr << "Invalid option. Use -d, -s, or -a." << std::endl;
        return 1;
    }

    int serverSocket, clientSocket;
    sockaddr_in serverAddr, clientAddr;
    socklen_t clientAddrSize = sizeof(clientAddr);

    // Create server socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Error opening socket!" << std::endl;
        return 1;
    }

    // Set up server address structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    // Bind the socket to the address
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error binding socket!" << std::endl;
        return 1;
    }

    // Listen for incoming connections
    listen(serverSocket, MAX_CLIENTS);

    // Define key paths for the Server
    std::string serverPrivateKey = "server_private.pem";
    std::string serverPublicKey = "server_public.pem";

    // Generate keys if they do not exist
    generateServerKeys(serverPrivateKey, serverPublicKey);

    logMessage("Server is listening on port " + std::to_string(port), LOG_SIMPLE);
    logMessage("Option: " + option, LOG_SIMPLE);

    std::string public_key = readPemFile("server_public.pem");
    
    if (!public_key.empty()) {
        std::cout << "PEM Public Key content:\n" << public_key << std::endl;
    } else {
        std::cerr << "Failed to read PEM file." << std::endl;
    }

    /*
    FILE* pubKeyFile = fopen(serverPublicKey.c_str(), "rb");
    if (!pubKeyFile) {
        std::cerr << "Failed to open public key file" << std::endl;
        return 1;
    }

    RSA* rsa = PEM_read_RSA_PUBKEY(pubKeyFile, NULL, NULL, NULL);
    cout << "rsa: " << rsa << endl;
    fclose(pubKeyFile);
    int rsaLen = RSA_size(rsa);
    std::string public_key(rsa, rsaLen);
    

    if (!rsa) {
        std::cerr << "Failed to read public key" << std::endl;
        return 1;
    }
    */

    // Accept and handle incoming client connections
    while (true) {
        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket < 0) {
            std::cerr << "Error accepting client connection!" << std::endl;
            continue;
        }
        logMessage("New client connected!", LOG_SIMPLE);

        // Spawn a worker thread to handle the client
        std::thread worker(workerThreadFunction, clientSocket, public_key);
        worker.detach();  // Detach thread to allow concurrent handling
    }

    shutdown(serverSocket, SHUT_RDWR);
    close(serverSocket);
    return 0;
}

void workerThreadFunction(int clientSocket, const std::string& public_key) {
    handleClient(clientSocket, public_key);
}

void handleClient(int clientSocket, const std::string& public_key) {
    char buffer[1024] = {0};
    int bytesRead = 0;
    
    std::string userName;
    while (true) {
        // Read the initial message from client
        memset(buffer, 0, sizeof(buffer)); // Clear buffer
        bytesRead = read(clientSocket, buffer, sizeof(buffer)); // Read message from client
        if (bytesRead < 0) {
            //std::cerr << "Error reading from client!" << std::endl;
            close(clientSocket);
            return;
        }
        
        
        std::string clientMessage(buffer, bytesRead);
        
        // Handle the client request based on message
        if (clientMessage.find("REGISTER#") == 0) {
            // Register client
            userName = clientMessage.substr(9);
            registerClient(clientSocket, userName);
        //比較strict的條件優先篩選
        } else if (clientMessage.find("TRANSFER#") == 0) {
            size_t delimiter = clientMessage.find("#");
            clientMessage = clientMessage.substr(delimiter + 1); //去掉TRANSFER#

            clientMessage = decryptMessageWithPrivateKey(clientMessage, "server_private.pem"); //解密來自payee的訊息
            std::cout << "Final Decrypted Message on Server: " << clientMessage << std::endl;

            // This indicates transaction format: fromUser#amount#toUser
            size_t firstDelimiter = clientMessage.find("#");
            size_t secondDelimiter = clientMessage.find("#", firstDelimiter + 1);

            std::string fromUser = clientMessage.substr(0, firstDelimiter);
            double amount = std::stod(clientMessage.substr(firstDelimiter + 1, secondDelimiter - firstDelimiter - 1));
            std::string toUser = clientMessage.substr(secondDelimiter + 1);

            cout << "processTransaction function called" << endl;
            processTransaction(clientSocket, fromUser, toUser, amount);
        } else if (clientMessage.find("#") != std::string::npos) {
            // Client login
            size_t delimiter = clientMessage.find("#");
            userName = clientMessage.substr(0, delimiter);
            int port = std::stoi(clientMessage.substr(delimiter + 1));
            loginClient(clientSocket, userName, port, public_key);
        } else if (clientMessage == "List") {
            // Send online list
            sendOnlineList(clientSocket, userName, public_key);
        
        } else if (clientMessage == "Exit") {
            // Client exit
            for (auto& account : accountsOnline) {
                if (account.accountName == userName) {
                    accountsOnline.erase(std::remove(accountsOnline.begin(), accountsOnline.end(), account), accountsOnline.end()); //
                    cout << "User " << userName << " has been removed from the online list." << endl;
                }
            }
            clientExit(clientSocket);
        } else {
            sendResponse(clientSocket, "Invalid message format.");
        }
    }
}

void registerClient(int clientSocket, const std::string& userName) {
    // Register the client in the system
    std::lock_guard<std::mutex> lock(mtx);
    for (auto& account : accountsOnline) {
        if (account.accountName == userName) {
            sendResponse(clientSocket, "210 FAIL");
            return;
        }
    }
    //可以再研究construcor的用法
    Account newAccount = {userName, 10000, "127.0.0.1", 0}; //這裡先假設ip為本地，可以再把user ip改成全域變數在這裡傳入
    accountsOnline.push_back(newAccount); //應該要等到client真的登入才加入？
    logMessage("Client registered: " + userName, LOG_SIMPLE);
    sendResponse(clientSocket, "100 OK");
}

void loginClient(int clientSocket, const std::string& userName, int port, const std::string& public_key) {
    std::cout << "loginClient function called" << std::endl;
    //std::lock_guard<std::mutex> lock(mtx);
    std::unique_lock<std::mutex> lock(mtx); // 使用 unique_lock 以便可以手動解鎖
    bool found = false;

    std::string clientIp = getClientIp(clientSocket);
    
    for (auto& account : accountsOnline) {
        if (account.accountName == userName) {
            found = true;
            account.portNum = port;
            account.ipAddress = clientIp; // 更新 IP 地址
            logMessage("Client logged in: " + userName, LOG_SIMPLE);
            /*
            string message;
            for (auto& account : accountsOnline) {
                message += account.accountName + "#" + account.ipAddress + "#" + std::to_string(account.portNum) + "\n";
            }
            logMessage("Online list:", LOG_SIMPLE);*/
            lock.unlock(); // 呼叫 sendOnlineList 前解鎖
            sendOnlineList(clientSocket, userName, public_key);
            break;
        }
    }
    if (!found) {
        sendResponse(clientSocket, "220 AUTH_FAIL");
    }
}

void sendOnlineList(int clientSocket, const std::string& userName, const std::string& public_key) {
    std::cout << "sendOnlineList function called" << std::endl;
    std::cout << "userName: " << userName << std::endl;
    std::lock_guard<std::mutex> lock(mtx);
    std::string response; //= "Account Balance:"
    //可以再apply適合的演算法快速找到資料庫中對應的account
    for (const auto& account : accountsOnline) {
        if (account.accountName == userName) { // 這裡是為了讓client知道自己的餘額（語法是對的嗎？）
            std::cout << "user found!\n" << account.accountName << std::endl;
            std::cout << "balance: " << account.balance << std::endl;
            response += std::to_string(account.balance) + "\n"; //balance
            //cout << "hi response: " << response << endl;
            break;
        }
    }
    cout << "public_key: " << public_key << endl;
    response += public_key + "\n"; // 這裡是為了讓client知道server的public key（未來要真的加入public key）
    //response += "Server Public Key: " + public_key + "\n";

    response += std::to_string(accountsOnline.size()) + "\n"; // 這裡是為了讓client知道有幾個帳戶

    for (const auto& account : accountsOnline) {
        response += account.accountName + "#" + account.ipAddress + "#" + std::to_string(account.portNum) + "\n";
    }
    cout << "response: " << response << endl;
    sendResponse(clientSocket, response);
    
    // If log level is set to -s or higher, show online list
    if (logLevel >= LOG_STATUS) {
        logMessage("Current online users:", LOG_STATUS);
        for (const auto& account : accountsOnline) {
            logMessage(account.accountName + "#" + account.ipAddress + "#" + std::to_string(account.portNum), LOG_STATUS);
        }
    }
}

void sendResponse(int clientSocket, const std::string& message) {
    write(clientSocket, message.c_str(), message.size());
    
    // If log level is set to -a, show each message sent
    if (logLevel == LOG_ALL) {
        logMessage("Sent to client: \n" + message, LOG_ALL);
    }
}

void clientExit(int clientSocket) {
    // Handle client exit logic
    write(clientSocket, "Bye", 3); //那哪裡有寫把client從accountsOnline中移除？ 
    close(clientSocket);
    
    logMessage("Client disconnected.", LOG_SIMPLE);

    if (logLevel >= LOG_STATUS) {
        logMessage("Current online users:", LOG_STATUS);
        for (const auto& account : accountsOnline) {
            logMessage(account.accountName + "#" + account.ipAddress + "#" + std::to_string(account.portNum), LOG_STATUS);
        }
    }
}

void logMessage(const std::string& message, LogLevel level) {
    if (level <= logLevel) {
        std::cout << message << std::endl;
    }
}

void processTransaction(int clientSocket, const std::string& fromUser, const std::string& toUser, double amount) {
    std::lock_guard<std::mutex> lock(mtx);
    Account* fromAccount = nullptr;
    Account* toAccount = nullptr;

    // 找出付款人和收款人的帳戶
    for (auto& account : accountsOnline) {
        if (account.accountName == fromUser) {
            fromAccount = &account;
        }
        if (account.accountName == toUser) {
            toAccount = &account;
        }
    }

    // 檢查帳戶是否存在
    if (fromAccount == nullptr) {
        sendResponse(clientSocket, "404 FROM_USER_NOT_FOUND");
        logMessage("Transaction failed: From user not found", LOG_SIMPLE);
        return;
    }
    if (toAccount == nullptr) {
        sendResponse(clientSocket, "404 TO_USER_NOT_FOUND");
        logMessage("Transaction failed: To user not found", LOG_SIMPLE);
        return;
    }

    // 檢查餘額是否足夠
    if (fromAccount->balance < amount) {
        sendResponse(clientSocket, "403 INSUFFICIENT_FUNDS");
        logMessage("Transaction failed: Insufficient funds", LOG_SIMPLE);
        return;
    }

    cout << "fromUser: " << fromUser << endl;
    cout << "toUser: " << toUser << endl;

    // 進行交易
    fromAccount->balance -= amount;
    toAccount->balance += amount;
    sendResponse(clientSocket, "200 TRANSACTION_SUCCESS"); //傳回給payee
    
    logMessage("Transaction success: " + fromUser + " sent " + std::to_string(amount) + " to " + toUser, LOG_SIMPLE);

    // 若 log level 設為 -a，顯示交易詳細信息
    if (logLevel == LOG_ALL) {
        logMessage("Updated balance for " + fromUser + ": " + std::to_string(fromAccount->balance), LOG_ALL);
        logMessage("Updated balance for " + toUser + ": " + std::to_string(toAccount->balance), LOG_ALL);
    }
}
