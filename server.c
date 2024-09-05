#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h> // biblioteca para criptografia e gerenciamento de certificados
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <asm-generic/socket.h>

void initialize_openssl() { // inicializa a biblioteca OpenSSL, não precisa chamar SSL_library_init() diretamente
  SSL_load_error_strings(); // carrega as mensagens de erro para facilitar diagnóstico caso algo der errado
  OpenSSL_add_ssl_algorithms(); // prepara a biblioteca para utilizar todos algoritmos de criptografia da OpenSSL
}

void cleanup_openssl() {
  EVP_cleanup();  // limpa a inicialização da biblioteca, liberando recursos associados, deve ser chamado no final
}

SSL_CTX* create_context() { // contexto SSl, configuração necessária para criar conexões seguras com SSL
  const SSL_METHOD* method; // método SSL, define o protocolo de criptografia
  SSL_CTX* ctx;

  method = TLS_server_method(); // define um método de criptografia adequado para o servidor
  ctx = SSL_CTX_new(method); // cria um novo contexto com um método SSL que define o protocolo de criptografia
  if(!ctx) {
    ERR_print_errors_fp(stderr);  // imprime erros se a criação falhar
    abort();  // encerra o programa se houver erro, tratamento do erro pode ser mais elegante em contexto de produção
  }
  return ctx;
}

void configure_context(SSL_CTX* ctx) {
  if(SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) { // carrega o certificado do servidor
    ERR_print_errors_fp(stderr);
    abort();
  }

  if(SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) { // carrega a chave privada associada ao certificado
    ERR_print_errors_fp(stderr);
    abort();
  }

  if (!SSL_CTX_check_private_key(ctx)) {  // verifica se a chave privada corresponde ao certificado
        fprintf(stderr, "A chave privada não corresponde ao certificado\n");
        abort();
    }
}

int create_server_socket(int port) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    // Criar o descritor de arquivo do socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) { // SOCK_STREAM = socket TCP, 0 = SO escolhe protocolo
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forçar a reutilização do endereço
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,&opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Definir o endereço e a porta
    address.sin_family = AF_INET; // AF_INET = IPv4
    address.sin_addr.s_addr = INADDR_ANY; // aceita conexões em qualquer endereço
    address.sin_port = htons(port);  // converte para a ordem de bytes da rede

    // Associar o socket ao endereço e porta
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }


    // Escutar por conexões
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return server_fd;
}

void handle_client(SSL* ssl) {
    char buffer[1024] = {0};
    int bytes;


    // Ler dados do cliente
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes > 0) {
        // Processar dados recebidos
        printf("Received: %s\n", buffer);
        // Enviar resposta
        const char* response = 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 10\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Olá Mundo";
        SSL_write(ssl, response, strlen(response));
    }
}

// Seria interessante implementar um redirect de http para https

int main() {
    int server_fd;
    SSL_CTX* ctx;
    SSL* ssl;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd;

    initialize_openssl(); // primeira coisa a se fazer é inicializar o OpenSSL
    ctx = create_context(); // cria o contexto da conexão
    configure_context(ctx); // configura o contexto

    server_fd = create_server_socket(4433); // cria o socket na porta 4433 ou outra de sua escolha

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len); // aceita conexão de clientes
        if (client_fd < 0) {  // cliente_fd é usada para comunicação com este cliente, server_fd volta a escutar novas conexões
            perror("accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);  // associa um objeto SSL ao socket aceito para criptografar a conexão

        if (SSL_accept(ssl) <= 0) { // aceita a conexão SSL
            ERR_print_errors_fp(stderr);
        } else {
            handle_client(ssl); // processa os dados do cliente
        }

        // encerra a conexão SSL
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    // limpa os recursos
    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
