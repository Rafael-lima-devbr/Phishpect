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

Composição phishing planejada:

- 150 OpenPhish;
- 150 PhishTank verificado e online.

Qualquer mudança de fonte exige aprovação antes da coleta final.

## Fontes

- Tranco com subdomínios: base dos domínios legítimos, com ID permanente da lista registrado no manifesto.
- Common Crawl CDXJ: URLs internas arquivadas, status 200 e MIME HTML.
- Catálogos/showcases oficiais: complemento determinístico para shared hosting, quando necessário.
- Fonte categórica documentada: necessária para marcar comércio/finanças sem inferência baseada no detector. Cloudflare Radar é opcional e não pode se tornar dependência obrigatória.
- OpenPhish Community Feed: phishing textual.
- PhishTank `online-valid`: phishing textual, verificado e online.

URLs reais de phishing nunca serão abertas. Os feeds serão tratados somente como dados.

## Seed e seleção

Seed: `phishpect-dataset-c-2026-10-15-v1`.

Dentro de cada estrato/fonte, os candidatos serão ordenados por SHA-256 de `seed + NUL + URL normalizada`. Os primeiros candidatos elegíveis preencherão a cota. O detector não participa da seleção.

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
- PhishTank com `verified=yes` e `online=yes`;
- origem, identificador e timestamp preservados por linha.

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

A lista histórica inclui A, B, candidatos e resultados anteriores. Diretórios de C são ignorados ao construir o índice para evitar autocontagem.

## Reputação

O Dataset C principal exclui toda entrada reconhecida por `reputation/threat-db.json` no estado congelado. O objetivo primário é medir a análise local. A avaliação ainda registrará disponibilidade, correspondência, fonte e classificação final. Uma correspondência inesperada não será removida depois dos resultados.

## Selamento

Antes da avaliação serão gerados:

- `evaluation/datasets/dataset-c.csv`;
- manifesto JSON;
- SHA-256 do CSV e das fontes;
- composição por estrato/fonte;
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
