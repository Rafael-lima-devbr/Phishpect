# Resultados do Dataset C

## Estado

A avaliação oficial do Dataset C foi concluída em 16/10/2026. O conjunto foi preparado e selado antes da primeira execução do detector congelado.

- 600 URLs;
- 300 legítimas e 300 phishing;
- 300 domínios registráveis distintos em cada classe;
- SHA-256 do dataset: `2ff32e3206f103e628b52ed46d474f08b09cdccbc47d61e3f1939a61a171dbd0`;
- seed: `phishpect-dataset-c-2026-10-15-v1`;
- referência do detector: commit `7e59a5b26e0eaf9f809fa63340ca97e47d2de7ab`.

O detector não participou da seleção das amostras e não foi recalibrado depois da execução oficial.

## Resultado

| Métrica | Valor |
|---|---:|
| TP | 207 |
| TN | 281 |
| FP | 19 |
| FN | 93 |
| Recall | 69,00% |
| Precisão | 91,59% |
| F1 | 78,71% |
| Acurácia | 81,33% |
| Falso alerta | 6,33% |

IC95% de Wilson:

- recall: 63,55%–73,97%;
- falso alerta: 4,09%–9,68%.

O conjunto é balanceado 50/50; precisão e acurácia descrevem este experimento e não estimam diretamente a prevalência/desempenho na web real.

## Interpretação

Os 19 falsos positivos se concentraram principalmente em casos legítimos difíceis envolvendo IDN/Punycode, hospedagem compartilhada e autenticação.

Entre os 93 falsos negativos:

- 40 tiveram score zero;
- 46 apresentaram apenas uma categoria de evidência;
- 86/93 tinham nenhuma evidência reconhecida ou somente uma categoria.

Isso reforça a limitação da análise somente por URL para phishing com aparência lexical comum.

## Reputação

O Dataset C excluiu previamente toda entrada reconhecida pela base congelada de reputação. O objetivo era medir a capacidade da análise local sem depender de blacklist.

Por isso, a ausência de contribuição da reputação em C era esperada e **não demonstra inutilidade da camada**. No uso real, uma correspondência continua sendo evidência complementar forte; a ausência de correspondência nunca é tratada como segurança.

## Rastreabilidade

- [Protocolo prévio](../../protocols/dataset-c-protocol.md)
- [Dataset selado](../../datasets/dataset-c.csv)
- [Manifesto](../../sources/dataset-c/manifest.json)

Este README registra o resultado posterior sem reescrever o protocolo pré-registrado.
