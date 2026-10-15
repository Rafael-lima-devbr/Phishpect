# Investigação prévia — corpus HTML

Status: investigação documental; nenhum corpus foi baixado ou executado.

## Phishpedia

O repositório oficial declara um benchmark de aproximadamente 30 mil páginas phishing, anotadas com URL, HTML, screenshot e marca-alvo. O repositório está sob CC0-1.0, mas o arquivo do dataset é distribuído separadamente por Google Drive. A licença do código não deve ser presumida como autorização automática para redistribuir todo o corpus externo.

Fonte: https://github.com/lindsey98/Phishpedia

Antes do uso será necessário:

- baixar somente após aprovação;
- verificar a estrutura real do arquivo;
- procurar termos/licença específicos do dataset;
- calcular hash do arquivo original;
- verificar se HTML está completo por amostra;
- identificar scripts, formulários e recursos externos;
- decidir se apenas manifesto/hashes poderão ser versionados.

## PhishIntention

A página experimental lista conjuntos de 25 mil páginas benignas e 25 mil páginas phishing CRP derivados do corpus Phishpedia, além de subconjuntos para transição e classificação. Os links também são externos. A página consultada não apresenta uma licença específica para redistribuição desses arquivos.

Fonte: https://sites.google.com/view/phishintention/experiment-structure

Como muitos conjuntos são derivados do Phishpedia, eles não devem ser tratados como uma segunda origem independente sem verificar IDs e sobreposição.

## Recomendação preliminar

Usar Phishpedia como primeira alternativa técnica, porque a documentação afirma explicitamente a presença de HTML e URL. PhishIntention pode fornecer rótulos/subconjuntos úteis, mas provavelmente compartilha amostras e exige controle de sobreposição.

Tamanho de 120 legítimas + 120 phishing permanece apenas referência, não decisão final.

## Modelo seguro de processamento

- manter arquivos originais fora do navegador comum;
- nunca executar JavaScript do corpus;
- parser DOM inerte, sem carregamento de recursos;
- rede completamente bloqueada;
- formulários e navegações desabilitados;
- cópia sanitizada separada do original;
- hash do original e da cópia;
- log determinístico de elementos/atributos removidos;
- registro de que sanitização ou ausência de recursos pode alterar sinais;
- fixtures sintéticas fora das métricas principais.

Conteúdo criado dinamicamente, iframe, Shadow DOM e envio por JavaScript serão limitações observadas. Não serão reconstruídos artificialmente.

## Questões ainda abertas

1. Licença específica dos arquivos do dataset.
2. Tamanho e formato do download.
3. Se cada amostra possui HTML bruto, assets e URL em formato facilmente associável.
4. Proporção de páginas cujo HTML depende de recursos externos.
5. Permissão para armazenar amostras no Git ou apenas manifests/hashes.
6. Tamanho definitivo e método de amostragem do corpus.
