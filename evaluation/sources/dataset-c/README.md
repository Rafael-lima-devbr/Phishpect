# Fontes do Dataset C

Este diretório receberá manifestos e metadados de aquisição. Arquivos brutos grandes ou com restrição de redistribuição podem permanecer fora do Git, desde que URL, timestamp, tamanho, SHA-256 e instruções de obtenção sejam preservados.

Nenhuma fonte oficial foi coletada nesta etapa. O script `scripts/collect-dataset-c-sources.js` inicia em modo seguro (`dry-run`) e somente acessa a rede com `--execute`.

O Tranco é preservado primeiro como ZIP bruto. Antes da coleta no Common Crawl, uma cópia deve ser extraída para CSV e ambos os arquivos devem receber SHA-256 no manifesto. A aquisição usa a variante com subdomínios (`top-1m-incl-subdomains.csv.zip`) e registra separadamente o ID permanente retornado por `top-1m-id?subdomains=true`.

Categorias `ecommerce` e `financial` devem vir de um mapa CSV cuja fonte esteja documentada, nunca de inferência pelo resultado do Phishpect. Candidatos de catálogos oficiais podem ser acrescentados pelo argumento `--supplement`, preservando origem e timestamp.
