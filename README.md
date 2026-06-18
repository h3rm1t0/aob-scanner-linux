# aob-scanner-linux
Uma prova de conceito (PoC) desenvolvida em C para demonstrar manipulação dinâmica de memória em processos Linux. A ferramenta utiliza a interface virtual /proc/[pid]/mem e /proc/[pid]/maps para contornar o ASLR, localizar assinaturas de bytes (AOB) em tempo de execução e aplicar Code Patching diretamente no segmento .text do processo alvo.
