#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <inttypes.h>

unsigned char payload_nop[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

struct Nodo {
    int dado;
    struct Nodo* proximo;
};

ssize_t busca_assinatura(unsigned char *buffer, size_t buffer_size, unsigned char *assinatura, size_t sig_size){
    for (size_t i = 0; i <= buffer_size - sig_size;i++){
        if (memcmp(&buffer[i],assinatura,sig_size) == 0){
            return i;
        }
    }
    return EXIT_FAILURE;
}

int exploit(int pid){
    char maps_path[255];
    char mem_path[255];
    int sucesso = 0;
    snprintf(maps_path,sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path,sizeof(mem_path), "/proc/%d/mem", pid);
    FILE *maps_fd = fopen(maps_path,"r");
    int mem_fd = open(mem_path, O_RDWR);

    if (!maps_fd || mem_fd <0){
      perror("Erro ao acessar fd de memória e mapa do processo.");
      return EXIT_FAILURE;  
    }

    unsigned char assinatura[] = {0x89, 0x87, 0xC0, 0x04, 0x00, 0x00};
    size_t sig_size = sizeof(assinatura);

    char line[500];
    while (fgets(line,sizeof(line),maps_fd)){
        uintptr_t start, end;
        char perms[5];
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start, &end, perms) == 3){
            
            if (strncmp(perms, "r-xp", 4) != 0) {
                continue;
            }
            
            ssize_t region_size = end - start;
            unsigned char *buffer = malloc(region_size);

            if (buffer) {
                if (pread(mem_fd,buffer,region_size,start) >0){
                    size_t offset_encontrado = busca_assinatura(buffer,region_size,assinatura, sig_size);

                    if (offset_encontrado != -1){
                        uintptr_t endereco_alvo = start + offset_encontrado;
                        ssize_t bytes_escritos = pwrite(mem_fd, payload_nop, sizeof(payload_nop),endereco_alvo);
                        if (bytes_escritos == sizeof(payload_nop)){
                            sucesso = 1;
                        } else {
                            printf("Falha ao tentar injetar o payload.\n");
                        }
                    }
                }
            free(buffer);
            }
        }
    }

    if (sucesso = 0){
        printf("Não foi possível localizar a assinatura na memória do processo.\n");
        return EXIT_FAILURE;
    } else {
        printf("Payload injetado com sucesso.\n");
    }

    fclose(maps_fd);
    close(mem_fd);

    return EXIT_FAILURE;
}

int ParseHl2(struct Nodo* lista_pid, char *nome_pid_hl2){
    size_t buffer_size;
    char buffer[255];
    char caminho[255];
    struct Nodo* atual = lista_pid;
    
    while (atual != NULL) {
        snprintf(caminho, sizeof(caminho), "/proc/%i/comm", atual->dado);
        FILE *arquivo = fopen(caminho, "r");
        if (arquivo){
            if (fgets(buffer, sizeof(buffer), arquivo) != NULL){
                buffer[strcspn(buffer, "\n")] = '\0';
                if (strcmp(buffer,nome_pid_hl2) == 0){            
                    fclose(arquivo);
                    printf("PID: %i | hl2_linux\n",atual->dado);
                    return atual->dado;
                } 
            }
            fclose(arquivo);
        }
    atual = atual->proximo;
    }
    return -1;

}
void append(struct Nodo** ref_lista_pid, int novo_dado){
    struct Nodo* novo_nodo = (struct Nodo*) malloc(sizeof(struct Nodo));
    struct Nodo* ultimo = *ref_lista_pid;
    novo_nodo->dado = novo_dado;
    novo_nodo->proximo = NULL;

    if (*ref_lista_pid == NULL){
        *ref_lista_pid = novo_nodo;
        return;
    }
    while(ultimo->proximo != NULL){
        ultimo = ultimo->proximo;
    }
    ultimo->proximo = novo_nodo;
} 

int e_numero(const char *str) {
    if (*str == '\0') return 0;
    while (*str){
        if (!isdigit(*str)) return 0;
        str++;
    }
    return 1;
}

int main(){                                                        
    char *nome_pid_hl2 = "hl2_linux";
    DIR *dir;
    struct dirent *entrada;
    struct Nodo* lista_pid = NULL;

    dir = opendir("/proc");
    if (dir == NULL){
        perror("Erro ao abrir /proc.");
        return EXIT_FAILURE;
    }
    
    while ((entrada = readdir(dir)) != NULL){
        if (entrada->d_type == DT_DIR && e_numero(entrada->d_name)){  // "entrada->d_type" simboliza o tipo de arquivo e "DT_DIR" é o tipo de arquivo diretório 
            int pid_proc = atoi(entrada->d_name);
            append(&lista_pid, pid_proc);
        }
    }
    closedir(dir);

    int pid_hl2 = ParseHl2(lista_pid, nome_pid_hl2);
    if (pid_hl2 == -1){
        perror("Não foi possível localizar o PID do processo de half-life 2.\n");
        return EXIT_FAILURE;
    }

    exploit(pid_hl2);

    return 0;
}
