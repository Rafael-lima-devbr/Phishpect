# Investigação prévia — corpus HTML

Status: investigação concluída para a avaliação quantitativa de análise pós-carregamento.

## Decisão desta rodada — PhreshPhish

Foi selecionado o split `test` do PhreshPhish v1.0.1, revisão `eabec4b7a66324b79cc8a0ad856d1731dc26fe1a`.

Motivos:

- licença explícita CC BY 4.0;
- pares URL–HTML para as duas classes;
- rótulos `benign` e `phish` na mesma fonte, reduzindo viés de formato entre classes;
- export Parquet auditável;
- split de teste já separado pelo publicador;
- artigo e dataset card públicos.

Fonte: https://huggingface.co/datasets/phreshphish/phreshphish

Artigo: https://arxiv.org/abs/2507.10854

O corpus do Phishpect usa 120 amostras de cada classe, selecionadas deterministicamente antes da execução do detector. A seleção, a sanitização e suas limitações estão definidas em `evaluation/protocols/page-analysis-evaluation.md`.

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

## Recomendação preliminar anterior

Phishpedia havia sido a primeira alternativa técnica, porque a documentação afirma explicitamente a presença de HTML e URL. Ela não foi adotada nesta rodada porque a licença do arquivo externo não ficou tão explícita quanto a licença do repositório e a distribuição por Google Drive dificultava uma aquisição mínima e reproduzível.

PhishIntention não foi tratado como origem independente porque deriva partes de seus conjuntos do Phishpedia. Phish360 e LNU-Phish também foram considerados, mas não superaram a combinação de licença explícita, associação URL–HTML e acesso reprodutível oferecida pelo PhreshPhish.

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

## Limitações registradas

1. Uma única fonte não representa toda a diversidade da web.
2. A amostra usa somente um shard do split de teste, embora aplique seleção determinística e domínio registrável único.
3. A projeção estática não executa scripts, iframes, Shadow DOM nem recursos externos.
4. Páginas cujo conteúdo relevante surge dinamicamente podem perder sinais.
5. O conjunto balanceado 50/50 não representa a prevalência real de phishing.
