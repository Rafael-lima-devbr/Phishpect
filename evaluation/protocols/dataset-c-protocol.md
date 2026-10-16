# Protocolo prévio — Dataset C

Status: **definido antes da coleta final e ainda não executado**.

## Objetivo

Medir a análise local de URLs da versão de referência do Phishpect em dados posteriores ao congelamento e não utilizados em A/B ou no refinamento. Não melhorar o detector.

## Versão avaliada

- Commit: `7e59a5b26e0eaf9f809fa63340ca97e47d2de7ab`
- Extensão: `0.4.0`
- Referência completa: `evaluation/protocols/reference-version.md`
- Fuso dos registros: `America/Bahia`

## Tamanho e composição

O conjunto final terá 600 URLs balanceadas:

- 300 legítimas;
- 300 phishing.

Composição legítima:

| Estrato primário | Quantidade |
|---|---:|
| `internal_general` | 90 |
| `authentication` | 45 |
| `long_or_query` | 45 |
| `shared_hosting` | 45 |
| `commerce_finance` | 30 |
| `idn_punycode` | 15 |
| `unusual_structure` | 30 |

Composição phishing aprovada para esta rodada:

- 300 OpenPhish;
- múltiplas capturas temporalmente separadas, feitas somente quando necessárias;
- intervalo mínimo de 12 horas entre tentativas de captura, sem repetição imediata quando o conteúdo permanecer idêntico;
- no máximo uma URL por domínio registrável no conjunto final;
- preservação do identificador, timestamp e hash de cada captura.

O PhishTank deixou de ser obrigatório após o endpoint público responder HTTP 429 e o cadastro de novos usuários estar temporariamente indisponível. Nenhuma fonte substituta será acrescentada silenciosamente. Usar apenas OpenPhish reduz a diversidade entre fornecedores e é uma limitação metodológica explícita desta rodada.

## Fontes

- Tranco com subdomínios: universo-base dos domínios legítimos, com ID permanente da lista registrado no manifesto.
- Common Crawl CDXJ: fonte opcional de URLs internas arquivadas, status 200 e MIME HTML. Instabilidade do serviço não pode bloquear o conjunto.
- Sitemaps e `robots.txt` publicados pelos próprios sites pertencentes ao universo Tranco: fonte complementar para URLs internas. Somente URLs HTTP(S) do mesmo domínio registrável são aceitas.
- Caminhos de autenticação definidos previamente (`/login`, `/signin`, `/account`, `/account/login`, `/auth/login`): aceitos somente quando um domínio Tranco retorna HTML e o redirecionamento final permanece no mesmo domínio registrável.
- GitHub REST API e GitHub Pages: fonte documental para `shared_hosting`. São usados apenas repositórios públicos que informam `has_pages=true`; a URL é derivada deterministicamente de proprietário/repositório e nunca vem de feed de phishing.
- Wikidata Query Service, propriedade de website oficial P856: fonte pública estruturada para `commerce_finance`. As classes consultadas e a consulta SPARQL são preservadas com a resposta bruta. Cloudflare Radar não é obrigatório.
- IDN/Punycode: domínio presente na lista Tranco permanente, servido por HTTPS e documentado por sitemap do próprio host ou por website oficial P856 do Wikidata. Apenas disponibilidade ou aparência visual não são suficientes.
- OpenPhish Community Feed: única fonte de phishing desta rodada, tratada exclusivamente como texto.

URLs reais de phishing nunca serão abertas. Os feeds serão tratados somente como dados. Resultados do detector, score ou classificação não participam da seleção.

## Seed e seleção

Seed: `phishpect-dataset-c-2026-10-15-v1`.

Dentro de cada estrato/fonte/captura, os candidatos serão ordenados por SHA-256 de `seed + NUL + URL normalizada`. Os primeiros candidatos elegíveis preencherão a cota. O detector não participa da seleção.

A precedência dos estratos legítimos é:

1. shared hosting;
2. IDN/Punycode;
3. comércio/finanças com categoria fornecida pela fonte;
4. autenticação no path;
5. URL longa, path longo ou pelo menos três parâmetros;
6. estrutura incomum;
7. página interna geral.

## Inclusão

- HTTP(S) sintaticamente válido;
- aquisição posterior ao registro da referência, sempre que a fonte permitir;
- legítimas com captura Common Crawl 200/HTML ou origem oficial documentada;
- legítimas internas, não apenas raízes;
- OpenPhish proveniente de captura bruta identificada e preservada;
- origem, identificador e timestamp preservados por linha.

## Coleta legítima complementar

As regras são definidas antes da observação dos candidatos:

- `internal_general`: URL interna publicada em sitemap do próprio site ou um dos caminhos fixos prévios (`/about`, `/help`, `/docs`, `/products`, `/news`) que retorne HTML no mesmo domínio registrável, sem se enquadrar em estrato de maior precedência;
- `authentication`: URL de sitemap contendo token de autenticação ou caminho fixo previamente definido, com resposta HTML e redirecionamento restrito ao mesmo domínio registrável;
- `long_or_query`: URL publicada em sitemap com pelo menos 100 caracteres, path com pelo menos 60 caracteres ou três parâmetros;
- `shared_hosting`: site GitHub Pages comprovado por repositório público `has_pages=true` ou candidato Tranco/Common Crawl sob sufixo compartilhado aprovado;
- `commerce_finance`: website oficial P856 de entidade classificada pelo Wikidata como banco, organização financeira, comércio eletrônico ou marketplace, usando uma URL interna publicada pelo próprio site;
- `idn_punycode`: candidato Tranco Punycode com sitemap no mesmo domínio ou website oficial P856 equivalente;
- `unusual_structure`: URL interna publicada pelo próprio site ou confirmada pelos mesmos caminhos fixos prévios cujo hostname, de acordo com os critérios congelados do protocolo, possui múltiplos subdomínios, hífens ou dígitos.

Respostas brutas, consultas, timestamps, hashes, rank Tranco, regra de seleção e evidência são registrados. O conteúdo visual da página e o resultado do Phishpect não são examinados.

## Exclusão e deduplicação

Os filtros são aplicados nesta ordem e têm contadores independentes:

1. URL inválida;
2. duplicata segundo a normalização congelada;
3. equivalência por hostname + porta + path, ignorando query e fragmento;
4. sobreposição normalizada com qualquer CSV histórico de `evaluation/` anterior a C;
5. sobreposição histórica por hostname + path;
6. correspondência na base de reputação congelada;
7. domínio presente na outra classe;
8. concentração: no máximo uma URL por domínio registrável em cada classe;
9. ausência de estrato legítimo elegível.

Para phishing, capturas são primeiro combinadas e deduplicadas. Além do domínio registrável, quando a fonte fornecer identificador de campanha ele será usado para impedir concentração; na ausência desse identificador, domínio registrável é o limite conservador de campanha.

A lista histórica inclui A, B, candidatos e resultados anteriores. Diretórios de C são ignorados ao construir o índice para evitar autocontagem.

## Reputação

O Dataset C principal exclui toda entrada reconhecida por `reputation/threat-db.json` no estado congelado. O objetivo primário é medir a análise local. A avaliação ainda registrará disponibilidade, correspondência, fonte e classificação final. Uma correspondência inesperada não será removida depois dos resultados.

## Selamento

Antes da avaliação serão gerados:

- `evaluation/datasets/dataset-c.csv`;
- manifesto JSON;
- SHA-256 do CSV e das fontes;
- composição por estrato/fonte;
- composição do phishing por captura;
- contagem de cada filtro;
- lista dos CSVs históricos consultados;
- seed e timestamp.

O manifesto terá o estado `sealed-not-evaluated`. A avaliação recusa arquivos cujo hash, tamanho ou composição não correspondam ao manifesto.

## Métricas

- TP, TN, FP e FN;
- recall;
- precision;
- F1;
- accuracy;
- false alert rate;
- IC95% de Wilson para recall e false alert rate.

Também serão preservados score, classificação local, contribuições, categorias, bônus de diversidade, sinais, motivos, reputação e classificação final. Serão geradas distribuições de score e frequências de categorias/motivos.

## Ambiente e reprodutibilidade

O registro de execução incluirá commit de referência, data/hora, timezone, Node, sistema, arquitetura, CPU, RAM, hashes, parâmetros, comando e arquivos gerados.

## Comando oficial previsto

O caminho e o hash finais ainda serão preenchidos antes da autorização. O formato será:

```powershell
node scripts/evaluate-dataset-c.js --dataset=evaluation/datasets/dataset-c.csv --manifest=evaluation/sources/dataset-c/manifest.json --output-dir=evaluation/results/dataset-c/official --confirm-official
```

Sem `--confirm-official`, o script apenas verifica hashes e informa que o detector não foi chamado. Resultados oficiais existentes nunca serão sobrescritos.

## Regra pós-resultado

Independentemente do desempenho, esta rodada não mudará pesos, thresholds, marcas, combinações ou regras. Erros poderão ser categorizados e documentados, mas não usados para substituir a avaliação oficial por uma execução ajustada.

## Limitações metodológicas pré-registradas

- A classe phishing usa apenas OpenPhish, reduzindo diversidade de fornecedores, processos de verificação e campanhas observadas.
- Capturas do feed comunitário são snapshots de curta duração e não representam toda a população de phishing.
- Tranco mede popularidade/agregação de rankings, não é um selo absoluto de benignidade; por isso URLs legítimas exigem evidência adicional publicada pelo próprio site ou fonte oficial estruturada.
- Sitemaps não cobrem necessariamente páginas de autenticação e podem favorecer sites com melhor infraestrutura de indexação.
- Common Crawl é complementar e sua disponibilidade pode variar durante a aquisição.
