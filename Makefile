# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17
LDFLAGS = -lstdc++fs -lssl -lcrypto

# Targets
SERVER_TARGET = server8_ssl
CLIENT_TARGET = client8_ssl

# Source files
SERVER_SRC = server4_ssl.cpp
CLIENT_SRC = client4_ssl.cpp

# Default target
all: $(SERVER_TARGET) $(CLIENT_TARGET)

# Compile server
$(SERVER_TARGET): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

# Compile client
$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

# Clean build files
clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET)

