# Avaliação da análise pós-carregamento

## Primeira avaliação quantitativa

A avaliação inicial da PAGE_ANALYSIS foi realizada com 240 pares URL–HTML do PhreshPhish v1.0.1: 120 legítimos e 120 phishing, em 240 domínios registráveis distintos.

Nenhuma URL do corpus foi visitada. O HTML foi tratado como dado e convertido em snapshots estáticos sanitizados.

| Modo | TP | TN | FP | FN | Recall | Precision | F1 | Accuracy | FAR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| URL-only | 4 | 120 | 0 | 116 | 3,33% | 100,00% | 6,45% | 51,67% | 0% |
| PAGE 1.0 | 2 | 118 | 2 | 118 | 1,67% | 50,00% | 3,23% | 50,00% | 1,67% |
| COMBINED 1.0 | 6 | 118 | 2 | 114 | 5,00% | 75,00% | 9,38% | 51,67% | 1,67% |

A combinação recuperou dois phishing que a URL não havia detectado e introduziu dois falsos positivos. O ganho de recall foi de 1,67 ponto percentual e o aumento da FAR também foi de 1,67 ponto percentual.

Essa primeira execução é a referência científica usada para discutir o ganho incremental da camada pós-carregamento.

## PAGE_ANALYSIS 2.0 — desenvolvimento

Depois da inspeção dos erros da primeira avaliação, foi criada a PAGE_ANALYSIS 2.0. O mesmo corpus passou, a partir desse momento, a ser **dado de desenvolvimento**.

A 2.0 mudou principalmente:

- localização de evidências por formulário/grupo estrutural;
- diferenciação entre identidade principal e menções incidentais;
- menor agregação entre regiões independentes;
- uso de `placeholder` e `aria-label` na identificação de campos;
- manutenção da política de privacidade e de nunca produzir `blocked` sozinha.

Comparação de desenvolvimento:

| Modo | TP | TN | FP | FN | Recall | Precision | F1 | Accuracy | FAR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PAGE 2.0 | 1 | 120 | 0 | 119 | 0,83% | 100% | 1,65% | 50,42% | 0% |
| COMBINED + PAGE 2.0 | 5 | 120 | 0 | 115 | 4,17% | 100% | 8,00% | 52,08% | 0% |

Foram removidos os dois falsos positivos anteriores, sem introdução de novos. Um verdadeiro positivo da versão 1.0 foi perdido porque dependia da agregação de sinais localizados em partes independentes da página.

Portanto, a 2.0 melhorou a coerência contextual e o controle de falsos positivos, mas **não apresentou ganho quantitativo de detecção** nesse corpus.

## Integridade metodológica

Os artefatos em `development-v2/` registram explicitamente:

- `status: development-comparison`;
- `independent_validation: false`;
- zero iterações de tuning orientado por métricas na comparação final;
- hashes do analisador e dos artefatos;
- transições de erros entre 1.0 e 2.0.

A decisão foi encerrar o tuning nessa etapa para evitar overfitting sobre o mesmo corpus.

## Arquivos

- [métricas comparativas](development-v2/metrics-comparison.json)
- [registro da execução](development-v2/run.json)
- [transições COMBINED](development-v2/transitions-combined-v1-v2.csv)
- [erros alterados](development-v2/changed-errors.csv)
- [documentação da PAGE_ANALYSIS 2.0](../../../docs/page-analysis.md)
