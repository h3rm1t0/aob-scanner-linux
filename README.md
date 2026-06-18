## AOB-Scanner-Linux
Uma prova de conceito (PoC) desenvolvida em C para demonstrar manipulação dinâmica de memória em processos Linux. A ferramenta utiliza a interface virtual /proc/[pid]/mem e /proc/[pid]/maps para contornar o ASLR, localizar assinaturas de bytes (AOB) em tempo de execução e aplicar Code Patching diretamente no segmento .text do processo alvo.
No caso do alvo em questão, a manipulação de memória tinha como objetivo deixar a munição infinita

## Objetivo
Entender melhor o mapeamento de memória de processos em ambientes linux, bem como utilizar de tecnicas para corrupção de memória durante o processo ativo e de maneira totalmente dinâmica (ASLR BYPASS).

## Aviso Educacional
Este projeto foi desenvolvido estritamente para fins de estudo em engenharia reversa, segurança de sistemas operacionais e desenvolvimento de sistemas de baixo nível. A técnica demonstrada deve ser utilizada apenas em ambientes controlados e laboratórios locais, não devendo ser aplicada em softwares de terceiros com proteções anti-cheat ativas (como VAC, BattlEye) ou jogos multiplayer.

## Arquitetura e Funcionamento
    - Descoberta do PID: Resolução automática do Process ID navegando pelo diretório virtual /proc.
    - Mapeamento de Memória: Leitura e parse do /proc/[pid]/maps filtrando apenas por regiões com permissão de execução (r-xp), otimizando a varredura e evitando Segmentation Faults.
    - AOB Scanning: Busca por uma matriz de bytes (assinatura Assembly) diretamente na memória bruta do processo usando pread.
    - Code Patching: Substituição de instruções originais por opcodes arbitrários (ex.: NOPs 0x90) em tempo de execução via pwrite, alterando a lógica do programa sem necessidade de arquivos intermediários.

## Setup de Ambiente de testes 
    OS: Ubuntu 24.04.4 LTS
    Kernel: 6.7.10-060710-generic
    Compilador: gcc version 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1)
    Alvo: Half-Life 2 (Linux Native) | BUILD ID: 19307283 | APP ID: 220
    Arquitetura| Alvo: x86 | Host: x86_64
    Build&Flags: gcc -o aob-scanner aob-scanner-linux.c
    OS Defense: ASLR Ligado (Address Space Layout Randomization)
