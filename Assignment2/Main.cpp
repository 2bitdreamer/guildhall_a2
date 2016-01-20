#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <list>

typedef void(*Command)(void *arg);

#pragma comment(lib, "ws2_32.lib")

const char* g_serverPort = "11412";
static char* AllocLocalHostName();

SOCKET BindAddress(const char* ip = "localhost", const char* port = g_serverPort, int af_family = AF_UNSPEC, int type = SOCK_STREAM);

struct ServerSocket {
	SOCKET m_socket;

	ServerSocket::ServerSocket(const char* ip = "localhost", const char* port = g_serverPort, int af_family = AF_UNSPEC, int type = SOCK_STREAM) {
		m_socket = BindAddress(ip, port, af_family, type);
	}

	ServerSocket::ServerSocket() :
		m_socket(INVALID_SOCKET) {}
};



struct ConnectedClient {
	std::string m_identifier;
	SOCKET m_socket;
};

unsigned int g_maxClients = 2;
std::string g_identifier = "INVALID";
std::list<ConnectedClient*> g_connectedClients;
std::map<std::string, Command> g_commands;
std::vector<ServerSocket> g_serverSockets;


class NetworkSystem
{
   private:
      char const *local_host_name;

   public:
      bool Init();
      void Deinit();

      const char* GetLocalHostname() const { return local_host_name; }
};


void CommandQuit(void* clientSocket) {
	SOCKET sock = (SOCKET)clientSocket;
	closesocket(sock);

	for (auto it = g_connectedClients.begin(); it != g_connectedClients.end(); ) {
		ConnectedClient* cc = *it;
		if (cc->m_socket == sock) {
			it = g_connectedClients.erase(it);
			break;
		}
		else {
			++it;
		}
	}
}

void CommandServerQuit(void* serverSocket) {

	(void*)serverSocket;
	for (auto it = g_connectedClients.begin(); it != g_connectedClients.end(); ++it) {
		ConnectedClient* cc = *it;
		SOCKET sock = cc->m_socket;
		closesocket(sock);
		delete cc;
	}

	g_connectedClients.clear();

	for (auto it = g_serverSockets.begin(); it != g_serverSockets.end(); ++it) {
		ServerSocket ss = *it;
		SOCKET sock = ss.m_socket;
		closesocket(sock);
	}
	
	g_serverSockets.clear();
}


//-------------------------------------------------------------------------------------------------------
static char* AllocLocalHostName()
{
   char buffer[256];

   if (SOCKET_ERROR == gethostname( buffer, 256 )) {
      return nullptr;
   }

   size_t len = strlen(buffer);
   if (len == 0) {
      return nullptr; 
   }

   char *ret = (char*)malloc(len + 1);
   memcpy( ret, buffer, len + 1 );

   return ret;
}

//-------------------------------------------------------------------------------------------------------
static std::string WindowsErrorAsString( DWORD error_id ) 
{
   if (error_id != 0) {
      LPSTR buffer;
      DWORD size = FormatMessageA( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
         NULL, 
         error_id, 
         MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT),
         (LPSTR)(&buffer),
         0, NULL );

      std::string msg( buffer, size );
      LocalFree( buffer );
             
      return msg;
   } else {
      return "";
   }
}

//-------------------------------------------------------------------------------------------------------
bool NetworkSystem::Init()
{
   WSADATA wsa_data;
   int error = WSAStartup( MAKEWORD(2, 2), &wsa_data );
   if (error == 0) {
      local_host_name = AllocLocalHostName();
      return true;
   } else {
      printf( "Failed to initialize WinSock.  Error[%u]: %s\n", error, WindowsErrorAsString(error).c_str() );
      return false;
   }
}

//-------------------------------------------------------------------------------------------------------
void NetworkSystem::Deinit() 
{
   free((void*) local_host_name);
   local_host_name = nullptr;

   WSACleanup();
}

//-------------------------------------------------------------------------------------------------------
// get sockaddr, IPv4 or IPv6:
static void* GetIPAddr(sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((sockaddr_in*)sa)->sin_addr);
    } else {
      return &(((sockaddr_in6*)sa)->sin6_addr);
    }
}

// This method of looping through addresses is going to be important for both
// hosting and connection. 
void PrintAddressesForHost( const char* host_name, const char* service )
{
   addrinfo hints;
   addrinfo *addr;

   if (nullptr == host_name) {
      host_name = "localhost";
   }

   memset( &hints, 0, sizeof(hints) );

   hints.ai_family = AF_UNSPEC;  

   hints.ai_socktype = SOCK_STREAM; // STREAM based, determines transport layer (TCP)
   hints.ai_flags = AI_PASSIVE; // used for binding/listening

   int status = getaddrinfo( host_name, service, &hints, &addr );
   if (status != 0) {
      printf( "Failed to create socket address: %s\n", gai_strerror(status) );
      return;
   }

   addrinfo *iter;
   for (iter = addr; iter != nullptr; iter = iter->ai_next) {
      char addr_name[INET6_ADDRSTRLEN];
      inet_ntop( iter->ai_family, GetIPAddr(iter->ai_addr), addr_name, INET6_ADDRSTRLEN );
      printf( "Address family[%i] type[%i] %s : %s\n", iter->ai_family, iter->ai_socktype, addr_name, service );
   }

   freeaddrinfo(addr);
}

//-------------------------------------------------------------------------------------------------------
SOCKET BindAddress( const char* ip /*= "localhost"*/, const char* port /*= g_serverPort*/, int af_family /*= AF_UNSPEC*/, int type /*= SOCK_STREAM*/ )
{
   SOCKET host_sock = INVALID_SOCKET;
   addrinfo hints;
   addrinfo *addr;

   if (ip == nullptr) {
      ip = "localhost";
   }

   memset( &hints, 0, sizeof(hints) );
   hints.ai_family   = af_family; 
   hints.ai_socktype = type;
   hints.ai_flags    = AI_PASSIVE;

   int status = getaddrinfo( ip, port, &hints, &addr );
   if (status != 0) {
      printf( "Failed to create socket address: %s\n", gai_strerror(status) );
   } else {
      // Alright, walk the list, and bind when able
      addrinfo *iter;
      
      for (iter = addr; iter != nullptr; iter = iter->ai_next) {
         char addr_name[INET6_ADDRSTRLEN];
         inet_ntop( iter->ai_family, GetIPAddr(iter->ai_addr), addr_name, INET6_ADDRSTRLEN );
         printf( "Attempt to bind on: %s : %s\n", addr_name, port );
         
         host_sock = socket( iter->ai_family, iter->ai_socktype, iter->ai_protocol );

         if (host_sock != INVALID_SOCKET) {
            if (bind( host_sock, iter->ai_addr, (int)(iter->ai_addrlen) ) == SOCKET_ERROR) {
				int error = WSAGetLastError();
				printf("Failed to bind socket: Socket Error[%i]\n", error);

               closesocket( host_sock );
               host_sock = INVALID_SOCKET;
            } else {
               // Connecting on address 
               printf( "Bound to : %s\n", addr_name );
               break;
			}
		 }
		 else {
			 int error = WSAGetLastError();
			 printf("Failed to create socket: Socket Error[%i]\n", error);
			 continue;
		 }
	  }

	  // We're done with the address, clean up my memory
	  freeaddrinfo(addr);
   }

   return host_sock;
}

void ReceiveData(int bufferSize, char* buffer)
{

	for (auto it = g_connectedClients.begin(); it != g_connectedClients.end(); ) {
		ConnectedClient* cc = *it;
		SOCKET& sock = cc->m_socket;
		int len = recv(sock, buffer, bufferSize, 0);
		const int error = WSAGetLastError();

		if (error != 0 && error != WSAEWOULDBLOCK) {
			std::string err = WindowsErrorAsString(WSAGetLastError());
			std::cout << err << std::endl;
			std::cout << "Closing Connection. " << std::endl;
			it = g_connectedClients.erase(it);
			closesocket(sock);
		}
		else if (error == WSAEWOULDBLOCK) {
			++it;
		}
		else {
			++it;
			buffer[len] = NULL;
			printf("Got data %s from ID %s\n", buffer, cc->m_identifier.c_str());

			std::string bufferString = std::string(buffer);
			std::transform(bufferString.begin(), bufferString.end(), bufferString.begin(), ::tolower);

			if (g_commands.find(bufferString) != g_commands.end()) {
				Command com = g_commands[bufferString];
				com(nullptr);
			}

			printf("Sending echo: %s\n", buffer);
			send(sock, buffer, strlen(buffer), 0);
		}

	}
}

void WaitForConnection(SOCKET& sock) {
	if (sock == INVALID_SOCKET) {
		printf("Failed to create listen socket.\n");
		std::cout << "Exiting...." << std::endl;
		_getch();
		exit(0);
	}

	u_long non_blocking = 1;
	u_long blocking = 0;

	sockaddr_storage their_addr;
	SOCKET theirSocket;

	const int bufferSize = 2048;
	char buffer[bufferSize];
	int addr_size = sizeof(their_addr);

	ioctlsocket(sock, FIONBIO, &non_blocking);

	int backlog_count = 8;
	if (listen(sock, backlog_count) == SOCKET_ERROR) {
		closesocket(sock);

		int error = WSAGetLastError();
		if (error == WSAESHUTDOWN || error == WSAECONNRESET || error == WSAENOTSOCK) {
			std::cout << "Server Shutting Down." << std::endl;
			_getch();
			exit(0);
		}

		printf("Failed to listen.  %s\n", WindowsErrorAsString(error).c_str());
		return;
	}

	//printf("Waiting for connections...\n");

	//printf("Waiting for accept....\n");
	theirSocket = accept(sock, (sockaddr*)&their_addr, &addr_size);

	if (theirSocket == SOCKET_ERROR) {
		const int error = WSAGetLastError();
		if (error == WSAEWOULDBLOCK) {
		}
		else {
			printf("Failed to accept: [%i] %s", error, WindowsErrorAsString(error).c_str());
		}
	}  
	else {
		printf("Got a connection; waiting for data!\n");
		bool isConnectedPastLogin = false;

		while (!isConnectedPastLogin) {
			ioctlsocket(theirSocket, FIONBIO, &blocking);

			int idLen = recv(theirSocket, buffer, bufferSize, 0);

			if (idLen == -1) {
				int error = WSAGetLastError();
				std::cout << WindowsErrorAsString(error) << std::endl;
				std::string hi;
				std::cin >> hi;
			}
			ConnectedClient* cc = new ConnectedClient();
			buffer[idLen] = '\0';
			cc->m_identifier = std::string(buffer);
			cc->m_socket = theirSocket;


			std::string clientID;

			bool alreadyFound = false;
			for (auto it = g_connectedClients.begin(); it != g_connectedClients.end(); ++it) {
				ConnectedClient* thisCC = *it;
				if (thisCC->m_identifier == std::string(buffer)) {
					std::cout << "Found ID " << thisCC->m_identifier << "Already!" << std::endl;
					alreadyFound = true;
					isConnectedPastLogin = false;
					break;
				}
			}
			if (!alreadyFound) {
				g_connectedClients.push_back(cc);
				isConnectedPastLogin = true;
				ioctlsocket(theirSocket, FIONBIO, &non_blocking);
				std::string okString = "OK";
				send(theirSocket, okString.c_str(), okString.size(), 0);
				std::cout << "Logging in client with ID " << cc->m_identifier << std::endl;

			}
			else {
				delete cc;
				std::string badString = "BAD";
				send(theirSocket, badString.c_str(), badString.size(), 0);
			}

			if (g_connectedClients.size() > g_maxClients) {
				CommandQuit((void*)theirSocket);
				_getch();
				exit(0);
			}
		}
	}
}


//-------------------------------------------------------------------------------------------------------
void ServerHost(const char* host_name, const char* port)
{
	ServerSocket sLocalIP = ServerSocket(host_name, port, AF_INET);
	ServerSocket sLocalhost = ServerSocket("127.0.0.1", port, AF_INET);

	g_serverSockets.push_back(sLocalhost);
	g_serverSockets.push_back(sLocalIP);

	Command quit = CommandQuit;
	Command serverQuit = CommandServerQuit;

	g_commands["quit"] = quit;
	g_commands["serverquit"] = serverQuit;
	
	const int bufferSize = 2048;
	char buffer[bufferSize];

	for (;;) {
		WaitForConnection(sLocalIP.m_socket);
		WaitForConnection(sLocalhost.m_socket);
		ReceiveData(2048, buffer);
	}
}

//htons: Host to network order

void ClientLoop(SOCKET& host_sock)
{
	char buf[4] = "BAD";

	while (!strcmp("BAD", buf)) {
		int sendResult = send(host_sock, g_identifier.c_str(), g_identifier.size(), 0);

		int error = WSAGetLastError();
		if (sendResult == 0 || error != 0) {
			std::cout << "The Server Has Ended" << std::endl;
			std::cout << "Press Any Key To Continue..." << std::endl;
			WSACleanup();
			_getch();
			exit(0);
		}

	
		int len = recv(host_sock, buf, 3, 0);
		error = WSAGetLastError();

		if (len == 0 || error != 0 ) {
			std::cout << "The Server Has Ended" << std::endl;
			std::cout << "Press Any Key To Continue..." << std::endl;
			WSACleanup();
			_getch();
			exit(0);
		}
		else {
			buf[len] = '\0';
			if (!strcmp("BAD", buf)) {
				std::cout << "ID Taken, Enter Again:" << std::endl;
				std::getline(std::cin, g_identifier);
			}
		}
	}

	std::cout << "Successfully Connected!" << std::endl;

	for (;;) {
		std::string message;
		std::getline(std::cin, message);

		int sendResult = send(host_sock, message.c_str(), (int)message.size(), 0);
		int error = WSAGetLastError();
		if (sendResult == 0 || error != 0) {
			std::cout << "The Server Has Ended" << std::endl;
			std::cout << "Press Any Key To Continue..." << std::endl;
			WSACleanup();
			_getch();
			exit(0);
		}

		if (message == "quit") {
			CommandQuit((void*)host_sock);
			std::cout << "Quitting...." << std::endl;
			std::cout << "Press Any Key To Continue..." << std::endl;
			WSACleanup();
			_getch();
			exit(0);
		}

		char buffer[128];
		int len = recv(host_sock, buffer, 128, 0);

		 error = WSAGetLastError();
		if (sendResult == 0 || error != 0) {
			std::cout << "The Server Has Ended" << std::endl;
			std::cout << "Press Any Key To Continue..." << std::endl;
			WSACleanup();
			_getch();
			exit(0);
		}

		if (len > 0) {
			buffer[len] = NULL;
			printf("Received data from client: %s\n", buffer);
		}


	}
}

//-------------------------------------------------------------------------------------------------------
void ClientJoin(const char* addrname, const char* port)
{
	SOCKET host_sock = INVALID_SOCKET;
	addrinfo hints;
	addrinfo *addr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	int status = getaddrinfo(addrname, port, &hints, &addr);
	if (status != 0) {
		printf("Failed to create socket: %s\n", gai_strerror(status));
	}
	else {
		addrinfo *iter;


		for (iter = addr; iter != nullptr; iter = iter->ai_next) {
			char addr_name[INET6_ADDRSTRLEN];
			inet_ntop(iter->ai_family, GetIPAddr(iter->ai_addr), addr_name, INET6_ADDRSTRLEN);
			printf("Attempt to bind on: %s\n", addr_name);

			host_sock = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol);

			if (host_sock != INVALID_SOCKET) {
				if (connect(host_sock, iter->ai_addr, (int)iter->ai_addrlen) == SOCKET_ERROR) {
					std::cout << "Could not connect to hostname " << addr_name << " on port " << port << std::endl;
					closesocket(host_sock);
					host_sock = INVALID_SOCKET;
				}
				else {
					// Connecting on address 
					printf("Connected to : %s\n", addr_name);
					ClientLoop(host_sock);
					break;
				}	
			}
		}

		freeaddrinfo(addr);
	}

	closesocket(host_sock);
}

//-------------------------------------------------------------------------------------------------------
int _cdecl main( int argc, char const **argv )
{
   NetworkSystem net;

   if (!net.Init()) {
      printf( "Failed to initialize net system.\n" );
      _getch();
      return false;
   }

   // List Addresses
   PrintAddressesForHost( net.GetLocalHostname(), g_serverPort );

   if ((argc <= 1) || (_strcmpi( argv[1], "host" ) == 0)) {
      printf( "Hosting...\n" );
      ServerHost( net.GetLocalHostname(), g_serverPort ); 
   } else if (argc > 2) {
	   char const *addr = argv[1];
      g_identifier = std::string(argv[2]);
      printf( "Now joining with ID \"%s\" to [%s]\n", g_identifier.c_str(), addr );
      ClientJoin( addr, g_serverPort);
   } else {
      printf( "Enter hostname and identifier\n" );
   }

   net.Deinit();

   printf( "Press any key to continue...\n" );
   _getch();
   return 0;
}

