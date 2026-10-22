# Protocolo — avaliação quantitativa da análise pós-carregamento

Status inicial: pré-registrado antes da aquisição e antes de qualquer execução do detector.

## Pergunta de pesquisa

Quanto a análise pós-carregamento recupera dos falsos negativos da análise somente de URL e quantos falsos alertas adicionais ela introduz, mantendo fixa a implementação congelada do Phishpect?

## Fonte e licença

O corpus usa exclusivamente o split `test` do **PhreshPhish v1.0.1**, revisão imutável `eabec4b7a66324b79cc8a0ad856d1731dc26fe1a`, distribuído no Hugging Face sob **CC BY 4.0**. A fonte contém pares URL–HTML reais das classes `benign` e `phish`. Usar uma única fonte para as duas classes reduz diferenças de coleta e de formato entre classes, mas não elimina vieses do corpus original.

- Dataset: https://huggingface.co/datasets/phreshphish/phreshphish
- Artigo associado: https://arxiv.org/abs/2507.10854
- API de aquisição: `https://datasets-server.huggingface.co/filter`
- Atribuição: PhreshPhish authors/contributors, CC BY 4.0.

Phishpedia, PhishIntention, Phish360 e LNU-Phish foram considerados. Eles não são usados nesta rodada por pelo menos uma destas razões: licença específica do arquivo não suficientemente explícita, distribuição externa de grande porte, associação URL–HTML menos prática ou risco maior de confundir diferenças entre fontes com diferenças entre classes.

## Composição pré-definida

- seed: `phishpect-page-corpus-2026-10-16-v1`;
- split: `test`;
- 120 páginas legítimas (`benign`);
- 120 páginas phishing (`phish`);
- total: 240;
- máximo de uma amostra por domínio registrável em cada classe;
- nenhum domínio registrável compartilhado entre classes;
- fixtures sintéticas existentes ficam fora das métricas.

## Aquisição e seleção

1. Consultar somente a API oficial do dataset ou seu export Parquet oficial e versionado, filtrando por rótulo.
2. Não requisitar, resolver nem abrir a URL contida em cada registro.
3. Adquirir um pool prefixado de até 500 linhas elegíveis por classe, em lotes de até 100, na ordem fornecida pela revisão congelada.
4. Aceitar apenas URL HTTP(S), HTML não vazio, identificador `sha256` da fonte presente, URL normalizada única, hash próprio do HTML único e domínio registrável ainda não usado. O campo `sha256` do PhreshPhish é tratado como identificador da captura, não como hash dos bytes da coluna HTML; o pipeline calcula e preserva separadamente o SHA-256 real do HTML recebido.
5. Ordenar candidatos por `SHA-256(seed + classe + sha256_da_fonte)` e selecionar deterministicamente 120 por classe.
6. Selecionar legítimas primeiro; excluir da classe phishing os domínios registráveis já selecionados na classe legítima.

A seleção não importa e não executa `analysis.js`, `page-analysis.js` ou `combined-analysis.js`.

## Tratamento inerte e sanitização

O HTML original é preservado como bytes UTF-8 e recebe SHA-256. Ele nunca é aberto em navegador. Um parser HTML sem JavaScript, rede ou renderização extrai somente a projeção observável pelo analisador atual:

- título;
- textos de `h1` e `h2`;
- atributos `alt` de imagens;
- formulários, métodos, ações e metadados dos campos.

São gerados separadamente:

1. `snapshot.json`: entrada efetivamente entregue a `analyzePage`;
2. `sanitized.html`: projeção HTML mínima e inerte para auditoria visual.

A cópia sanitizada contém somente texto escapado, imagens sem `src`, formulários sem destino externo e campos desabilitados. Não contém scripts, estilos, links, iframes, objetos, mídia, meta-refresh, handlers de eventos ou URLs de recursos. A ação e o método originais permanecem apenas no snapshot de dados, nunca como comportamento executável.

Limitação: scripts e recursos removidos não são executados; portanto, DOM criado dinamicamente, iframes, Shadow DOM e conteúdo dependente de rede não aparecem. A avaliação mede a implementação atual sobre a projeção estática disponível no corpus, não uma navegação real.

## Selamento

Antes de importar o detector, o pipeline deve:

- validar exatamente 120/120;
- validar URLs, hashes e ausência de duplicatas;
- validar 240 domínios registráveis distintos;
- produzir `corpus-manifest.json` com fontes, regras, hashes e transformações;
- calcular o hash canônico do corpus;
- marcar `sealed-not-evaluated` e `detector_executed: false`.

Nenhuma amostra pode ser trocada após a inspeção de resultados.

## Modalidades e decisão binária

- URL-only: `analyzeUrl`; `safe` é negativo, `suspicious`/`blocked` são positivos.
- PAGE-only: `analyzePage`; `safe` é negativo e `suspicious` é positivo.
- COMBINED: `combineAnalyses` com o resultado local de URL e de página, sem reputação externa; `safe` é negativo, `suspicious`/`blocked` são positivos.

As três modalidades recebem exatamente as mesmas 240 amostras. O avaliador recusa corpus não selado, hash divergente, resultados preexistentes ou detector divergente da referência congelada.

## Métricas

Para cada modalidade: TP, TN, FP, FN, recall, precision, F1, accuracy e false alert rate. Intervalos de confiança de 95% usam Wilson para recall, precision, accuracy e FAR. O F1 é relatado pontualmente.

O corpus é balanceado artificialmente em 50/50. Precision e accuracy não representam diretamente a prevalência nem o desempenho esperado na web real.

## Transições

Serão preservadas todas as transições URL-only → COMBINED, com destaque para:

- FN → TP (phishing recuperado);
- TN → FP (falso alerta introduzido);
- TP → TP;
- TN → TN;
- TP → FN, esperada como impossível porque a combinação preserva `suspicious` e `blocked` da URL.

## Regra pós-execução

Após a primeira execução, erros podem ser analisados, mas o detector não será alterado nem reexecutado sobre este corpus como se ainda fosse validação independente. Se os resultados orientarem uma versão futura, o corpus passa a ser desenvolvimento dessa versão.
