#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Function to perform ping
void pingHost(const char* host) {
    std::string command = "ping -c 4 ";
    command += host;
    std::system(command.c_str());
}

// Function to send HTTP request and get server version
void detectHTTPVersion(const char* host) {
    struct sockaddr_in server_addr;
    int sockfd;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);
    server_addr.sin_addr.s_addr = inet_addr(host);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
        std::string request = "HEAD / HTTP/1.1\r\nHost: ";
        request += host;
        request += "\r\nConnection: close\r\n\r\n";

        if (send(sockfd, request.c_str(), request.length(), 0) != -1) {
            char buffer[1024] = {0};
            recv(sockfd, buffer, sizeof(buffer), 0);

            std::string response(buffer);
            size_t pos = response.find("Server:");
            if (pos != std::string::npos) {
                std::cout << response.substr(pos + 8, response.find("\r\n", pos) - pos - 8) << std::endl;
            } else {
                std::cout << "Version detection not available." << std::endl;
            }
        }
    }

    close(sockfd);
}

// Function to send HTTPS request and get server version
void detectHTTPSVersion(const char* host) {
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        std::cerr << "Error creating SSL context." << std::endl;
        return;
    }

    SSL* ssl = SSL_new(ctx);
    if (ssl == NULL) {
        std::cerr << "Error creating SSL structure." << std::endl;
        SSL_CTX_free(ctx);
        return;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }

    struct hostent* server = gethostbyname(host);
    if (server == NULL) {
        std::cerr << "Error resolving hostname." << std::endl;
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(443);
    server_addr.sin_addr.s_addr = *((unsigned long*)server->h_addr);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        perror("Connection failed");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }

    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        std::cerr << "SSL handshake failed." << std::endl;
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }

    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        char* certInfo = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        std::cout << "Server certificate: " << certInfo << std::endl;
        free(certInfo);
        X509_free(cert);
    } else {
        std::cerr << "No server certificate." << std::endl;
    }

    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

// Function to perform SSH version detection
void detectSSHVersion(const char* host) {
    // Placeholder for SSH version detection
    std::cout << "SSH version detection placeholder" << std::endl;
}

// Function to perform FTP version detection
void detectFTPVersion(const char* host) {
    // Placeholder for FTP version detection
    std::cout << "FTP version detection placeholder" << std::endl;
}

// Function to perform Telnet version detection
void detectTelnetVersion(const char* host) {
    // Placeholder for Telnet version detection
    std::cout << "Telnet version detection placeholder" << std::endl;
}

// Function to perform port scanning
void scanPort(const char* host, int port) {
    struct sockaddr_in addr;
    int sockfd;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        std::cout << "Port " << port << " is open" << std::endl;
        if (port == 80) {
            std::cout << "HTTP version: ";
            detectHTTPVersion(host);
        } else if (port == 443) {
            std::cout << "HTTPS version: ";
            detectHTTPSVersion(host);
        } else if (port == 22) {
            std::cout << "SSH version: ";
            detectSSHVersion(host);
        } else if (port == 21) {
            std::cout << "FTP version: ";
            detectFTPVersion(host);
        } else if (port == 23) {
            std::cout << "Telnet version: ";
            detectTelnetVersion(host);
        }
        std::cout << std::endl;
    }

    close(sockfd);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <host>" << std::endl;
        return 1;
    }

    const char* host = argv[1];

    // Ping the host
    std::cout << "Pinging " << host << "..." << std::endl;
    pingHost(host);

    // Scan common ports (e.g., HTTP, HTTPS, SSH, FTP, Telnet)
    int ports[] = {80, 443, 22, 21, 23}; // Add more ports as needed
    for (int port : ports) {
        std::cout << "Scanning port " << port << "..." << std::endl;
        scanPort(host, port);
    }

    return 0;
}
