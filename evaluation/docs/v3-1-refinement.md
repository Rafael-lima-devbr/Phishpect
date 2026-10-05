# Refinamento V3.1 — diversidade de evidências

## Metodologia

Os Datasets A e B foram usados para inspecionar falsos negativos, selecionar categorias, ajustar pesos e avaliar a V3.1. Portanto, ambos são **dados de desenvolvimento** e não validação independente. Nenhum Dataset C foi criado.

A V2 e a V3 originais foram preservadas em `analysis-v2.js` e `analysis-v3.js`. A extensão usa a V3.1 em `analysis.js`.

## 1. Análise dos falsos negativos da V3

### Características individuais

| Característica nos falsos negativos V3 | Dataset A (65 FN) | Dataset B (81 FN) |
| --- | ---: | ---: |
| HTTP | 31 | 40 |
| URL > 150 caracteres | 0 | 1 |
| Path longo | 0 | 0 |
| Hostname longo | 0 | 1 |
| Muitos subdomínios | 0 | 0 |
| Três ou mais hífens | 2 | 3 |
| Quatro ou mais dígitos | 11 | 10 |
| Alta proporção de dígitos | 8 | 5 |
| Autenticação no hostname | 0 | 0 |
| Autenticação no path | 4 | 0 |
| Marca exata fora do domínio oficial | 0 | 0 |
| Possível typosquatting | 0 | 0 |
| Shared hosting | 28 | 26 |
| Encurtador | 3 | 2 |
| Punycode | 0 | 0 |
| Userinfo/@ | 0 | 0 |
| Cinco ou mais query parameters | 0 | 1 |
| Alta entropia | 3 | 11 |

Marca, Punycode e autenticação no hostname aparecem com zero entre os falsos negativos porque a V3 já detectava os casos em que esses sinais eram suficientemente fortes. A maior oportunidade estava na combinação de infraestrutura compartilhada, transporte inseguro e estrutura anormal.

### Combinações em todos os phishings

| Par de categorias | Phishing A | Legítimas A | Phishing B | Legítimas B |
| --- | ---: | ---: | ---: | ---: |
| Infraestrutura + transporte | 20 | 0 | 21 | 0 |
| Infraestrutura + estrutura | 18 | 0 | 17 | 0 |
| Estrutura + transporte | 8 | 0 | 13 | 0 |
| Infraestrutura + path/query | 3 | 0 | 0 | 0 |
| Autenticação + infraestrutura | 1 | 0 | 1 | 0 |

As legítimas de A/B são simples e não cobrem adequadamente aplicações HTTP em plataformas compartilhadas. Logo, os zeros acima não podem ser interpretados como garantia de falso alerta zero em produção.

Entre os falsos negativos, 19 URLs do A e 22 do B não tinham nenhuma categoria reconhecida pela V3. Outros 10 no A e 20 no B tinham somente HTTP. Recuperar esses casos aumentando HTTP isoladamente repetiria o erro da V2 e foi deliberadamente evitado.

Os dados agregados reproduzíveis estão em `evaluation/results/refinement/v3-feature-analysis.json`, gerado por `scripts/analyze-v3-errors.js`.

## 2. Regra de diversidade da V3.1

### Categorias e tetos

| Categoria | Evidências | Teto |
| --- | --- | ---: |
| Identidade | marca fora do domínio, typo, Punycode, IP, userinfo | 30 |
| Autenticação | termos no hostname | 12 |
| Estrutura | hostname longo, subdomínios, hífens, proporção de dígitos, entropia | 15 |
| Transporte | HTTP | 6 |
| Path/query | comprimento, parâmetros, termos e marca apenas no path | 10 |
| Infraestrutura | shared hosting e encurtador | 10 |

Vários sinais da mesma categoria são somados somente até o teto. Assim, hífens, dígitos e entropia podem fortalecer `estrutura`, mas não fingem ser três categorias independentes.

O threshold é 24. Além do score, a URL precisa cumprir ao menos uma condição contextual:

- marca exata fora de domínio oficial;
- marca concatenada conservadoramente com contexto, como marca + `support`/`notify`;
- marca/typo + autenticação no hostname;
- Punycode + possível marca;
- userinfo + marca;
- pelo menos duas categorias, incluindo identidade, autenticação ou infraestrutura;
- transporte + estrutura com ao menos duas evidências estruturais;
- marca no path combinada com outra categoria;
- ou três categorias independentes.

Os bônus de diversidade são +10 para duas categorias, +14 para três e +18 para quatro ou mais. Um único sinal fraco permanece abaixo do threshold e inelegível.

### Pesos principais

- HTTP: 6, somente categoria transporte.
- URL longa: 5; path longo, autenticação no path e muitos parâmetros: 4; query de autenticação: 3.
- Marca apenas no path: 8, ainda dependente de outra categoria.
- Hostname longo, muitos subdomínios, muitos hífens, alta proporção de dígitos e alta entropia: 5 cada, limitados pelo teto estrutural.
- Autenticação no hostname: 8; múltiplos termos: +4 dentro do mesmo teto.
- IP: 18; Punycode: 16; userinfo: 20; typo: 18; marca exata/composta: 24.
- Shared hosting: 9; encurtador: 10.

O prefixo técnico `xn--` não conta como hífen estrutural. Isso impede que Punycode legítimo crie diversidade artificial.

## 3. Mudanças de cobertura

A lista de hospedagem compartilhada foi ampliada apenas com provedores multi-tenant identificáveis: `gitbook.io`, `godaddysites.com`, `zapier.app`, `workers.dev`, `duckdns.org`, `amplifyapp.com` e `edgeone.dev`. Esses domínios não geram alerta sozinhos.

A lista explícita de marcas ganhou Facebook, Discord, Ledger, MetaMask, DocuSign e Yahoo, com seus domínios oficiais. `discord.gg` foi incluído como oficial depois que a primeira calibração da V3.1 revelou esse falso positivo.

Marca no path é um sinal fraco. Ela só participa da decisão quando combinada, por exemplo, com shared hosting, encurtador ou HTTP.

## 4. Resultados V2 x V3 x V3.1

### Dataset A — desenvolvimento

| Versão | TP | FN | FP | TN | Recall | Precision | F1 | False alert rate | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| V2 | 62 | 38 | 1 | 99 | 62% | 98,41% | 76,07% | 1% | 80,5% |
| V3 | 35 | 65 | 0 | 100 | 35% | 100% | 51,85% | 0% | 67,5% |
| V3.1 | 60 | 40 | 0 | 100 | 60% | 100% | 75,00% | 0% | 80,0% |

### Dataset B — desenvolvimento

| Versão | TP | FN | FP | TN | Recall | Precision | F1 | False alert rate | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| V2 | 59 | 41 | 1 | 99 | 59% | 98,33% | 73,75% | 1% | 79,0% |
| V3 | 19 | 81 | 0 | 100 | 19% | 100% | 31,93% | 0% | 59,5% |
| V3.1 | 55 | 45 | 0 | 100 | 55% | 100% | 70,97% | 0% | 77,5% |

A camada de reputação não alterou os resultados porque A/B foram construídos sem sobreposição com o snapshot local.

## 5. Falsos negativos recuperados da V3

- Dataset A: 25 recuperados, zero detecções da V3 perdidas.
- Dataset B: 36 recuperados, zero detecções da V3 perdidas.

Combinações mais frequentes entre as recuperações:

- A: transporte + path/query + infraestrutura (8); transporte + infraestrutura (6); estrutura + transporte + path/query + infraestrutura (4); estrutura + infraestrutura (3).
- B: transporte + infraestrutura (10); estrutura + infraestrutura (6); transporte + path/query + infraestrutura (4); estrutura + transporte + path/query (3); estrutura + transporte + path/query + infraestrutura (3).

As listas completas contêm URL, scores, reasons, categorias, score por categoria e bônus de diversidade:

- `dataset-a-v3-to-v3-1-recovered.csv`
- `dataset-b-v3-to-v3-1-recovered.csv`

## 6. Comparação de cobertura com a V2

A V3.1 não é apenas um subconjunto da V2:

- A: recuperou 11 phishings que a V2 perdia e deixou de marcar 13 que a V2 detectava; saldo de -2 TP.
- B: recuperou 15 phishings que a V2 perdia e deixou de marcar 19 que a V2 detectava; saldo de -4 TP.

As detecções perdidas em relação à V2 estão documentadas em `dataset-*-v2-to-v3-1-lost-detections.csv`. Muitos desses casos dependiam de HTTP ou vocabulário isolado, comportamento que a V3.1 não restaura.

## 7. Falsos positivos e regressões

Na calibração intermediária, `https://discord.gg/` foi marcado porque apenas `discord.com` estava listado como oficial. A lista oficial foi corrigida antes da medição final.

Resultados finais:

- falsos positivos A: 0;
- falsos positivos B: 0;
- novos falsos positivos em relação à V3: 0;
- detecções da V3 perdidas pela V3.1: 0.

As listas finais de falsos positivos estão vazias além do cabeçalho. Isso é resultado observado, não objetivo forçado nem estimativa realista de produção.

## 8. Falsos negativos restantes

- Dataset A: 40.
- Dataset B: 45.

As listas completas estão em `dataset-a-v3-1-false-negatives.csv` e `dataset-b-v3-1-false-negatives.csv`. Muitos casos restantes têm URL lexicalmente neutra, apenas HTTP ou nenhuma evidência reconhecida. Detectá-los exigiria reputação mais atual, sinais de conteúdo/DOM ou regras frágeis específicas do dataset.

## 9. Riscos e limitações

- A/B orientaram diretamente a V3.1; os resultados medem desenvolvimento, não generalização.
- A inclusão de provedores multi-tenant observados nos erros pode superestimar desempenho em campanhas semelhantes.
- As legítimas de A/B são majoritariamente raízes de sites populares e sub-representam páginas benignas em shared hosting, URLs HTTP e aplicações com hostnames aleatórios.
- A lista de marcas continua manual e pequena.
- A análise lexical não identifica phishing com URL neutra em domínio comprometido.
- O falso alerta real pode ser maior do que 0%, especialmente para projetos legítimos em infraestrutura compartilhada.

## 10. Recomendação

A V3.1 apresenta equilíbrio claramente melhor que a V3: recupera 25/36 detecções, não perde nenhum acerto da V3 e mantém os princípios estruturais.

Em comparação com a V2, a V3.1 fica 2 pontos percentuais abaixo no recall do A e 4 pontos abaixo no B, mas elimina o falso alerta observado e, principalmente, não permite HTTP, comprimento ou termos isolados acionarem alerta. Portanto, **a V3.1 é a melhor candidata arquitetural para congelamento e validação**, mas ainda não deve ser declarada superior em produção.

O próximo passo correto é congelar a V3.1 e construir um Dataset C temporalmente novo, com forte presença de legítimas difíceis: shared hosting, HTTP, Punycode legítimo, URLs longas, login oficial, muitos parâmetros, hostnames com hífens/dígitos e encurtadores. Qualquer ajuste feito após consultar C deverá virar uma V3.2/V4 e exigir outro conjunto reservado.
