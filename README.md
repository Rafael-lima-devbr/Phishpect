# Phishpect

Extensão experimental para Microsoft Edge que combina **análise local baseada em regras**, **reputação local** e **análise estrutural pós-carregamento** para identificar páginas potencialmente fraudulentas e intervir de acordo com o nível de risco.

**Status:** etapa técnica atual encerrada e resultados experimentais consolidados para documentação científica.

<p align="center">
  <img width="62%" alt="Phishpect browser extension interface" src="https://github.com/user-attachments/assets/d88ee44d-ad87-46ec-b604-99d0219cf3d9" />
</p>

## Visão geral

O Phishpect mantém três fontes/resultados separados:

1. **URL_ANALYSIS** — a V3.1 analisa protocolo, hostname, domínio registrável, subdomínios, caminho e query, agrupando sinais em categorias e exigindo contexto ou diversidade de evidências.
2. **Reputação local** — consulta um snapshot derivado do feed ativo do projeto open source [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database). Uma correspondência é evidência forte; ausência de correspondência **não significa segurança**.
3. **PAGE_ANALYSIS** — depois de `DOMContentLoaded`, observa metadados de formulários, campos, destinos e identidade contextual sem ler valores digitados.

A decisão final pode ser:

| Resultado | Comportamento |
|---|---|
| `safe` | navegação liberada |
| `suspicious` | mostra os motivos e permite voltar ou continuar |
| `blocked` | reservado a evidências mais fortes, como correspondência na reputação ou casos controlados de teste |

A PAGE_ANALYSIS nunca produz `blocked` sozinha.

## Estado experimental

### Evolução da análise de URL

| Avaliação | Recall | Falso alerta | Acurácia |
|---|---:|---:|---:|
| V1 — Dataset A | 2% | 0% | 51% |
| V2 — Dataset A | 62% | 1% | 80,5% |
| V2 — Dataset B | 59% | 1% | 79% |
| V3 — Dataset A | 35% | 0% | 67,5% |
| V3 — Dataset B | 19% | 0% | 59,5% |
| V3.1 — Dataset A | 60% | 0% | 80% |
| V3.1 — Dataset B | 55% | 0% | 77,5% |
| **V3.1 congelada — Dataset C** | **69,00%** | **6,33%** | **81,33%** |

A e B foram usados durante o refinamento da V3/V3.1 e, portanto, são dados de desenvolvimento para essas versões. O **Dataset C** foi construído depois do congelamento da referência, selado antes da primeira execução e possui 600 URLs: 300 legítimas e 300 phishing, com um domínio registrável por amostra em cada classe.

Na execução oficial de C foram obtidos **TP=207, TN=281, FP=19 e FN=93**, com precisão de **91,59%** e F1 de **78,71%**. O conjunto é artificialmente balanceado, então precisão e acurácia não devem ser extrapoladas diretamente para a web real.

A reputação não alterou C **por desenho experimental**: entradas já reconhecidas pela base congelada foram removidas antes do selamento para medir a capacidade da análise local sem depender de blacklist. Isso não torna a reputação inútil; no uso real, uma correspondência continua sendo uma evidência complementar forte.

Detalhes: [protocolo do Dataset C](evaluation/protocols/dataset-c-protocol.md) e [resumo dos resultados](evaluation/results/dataset-c/README.md).

### Avaliação pós-carregamento

A primeira avaliação quantitativa da camada de página usou 240 pares URL–HTML do **PhreshPhish v1.0.1**: 120 legítimos e 120 phishing, em 240 domínios registráveis distintos. As URLs não foram visitadas; o HTML foi tratado como dado e convertido em snapshots estáticos sanitizados.

| Modo | Recall | Precisão | F1 | FAR |
|---|---:|---:|---:|---:|
| URL-only | 3,33% | 100,00% | 6,45% | 0% |
| PAGE-only 1.0 | 1,67% | 50,00% | 3,23% | 1,67% |
| COMBINED 1.0 | 5,00% | 75,00% | 9,38% | 1,67% |

A combinação recuperou dois phishing que a URL não detectou, mas também introduziu dois falsos positivos. O ganho foi mensurável, porém não demonstrou benefício líquido convincente nessa versão e nesse corpus.

Os erros observados motivaram a **PAGE_ANALYSIS 2.0**, que passou a localizar evidências por formulário/grupo estrutural e a distinguir melhor identidade principal de menções incidentais em rodapés, links sociais e badges de aplicativos. Como o mesmo corpus orientou esse refinamento, seus resultados seguintes são **de desenvolvimento, não validação independente**:

- PAGE 2.0: TP=1, TN=120, FP=0, FN=119; recall 0,83%; FAR 0%.
- COMBINED com PAGE 2.0: TP=5, TN=120, FP=0, FN=115; recall 4,17%; precisão 100%; F1 8,00%; acurácia 52,08%; FAR 0%.

Os dois falsos positivos anteriores foram removidos, mas um verdadeiro positivo da versão anterior também foi perdido. Isso reforçou a decisão de **encerrar o tuning nessa etapa** em vez de continuar ajustando regras sobre o mesmo corpus.

Detalhes: [PAGE_ANALYSIS 2.0](docs/page-analysis.md) e [resultados da avaliação de página](evaluation/results/page-analysis/README.md).

## Fluxo atual

```text
URL
 ├─> V3.1
 └─> reputação local
        |
        v
   URL_ANALYSIS

Página carregada
 └─> PAGE_ANALYSIS 2.0
        |
        v
URL_ANALYSIS + PAGE_ANALYSIS
        |
        v
  COMBINED_ANALYSIS
        |
        v
 safe / suspicious / blocked
```

Cliques primários comuns podem ser analisados antes de sair da página. Outras navegações são observadas pelo service worker; pelas limitações do Manifest V3, uma requisição pode começar antes do redirecionamento para a tela de aviso.

<p align="center">
  <img width="58%" alt="Phishpect risk classification screen" src="https://github.com/user-attachments/assets/857dbf90-e6a5-45be-89a4-608ac4f4cead" />
</p>

## Arquitetura

| Arquivo / diretório | Responsabilidade |
|---|---|
| `analysis.js` | V3.1 usada pela extensão |
| `analysis-v3.js` | V3 preservada para comparação |
| `analysis-v2.js` | V2 preservada para comparação |
| `page-analysis.js` | PAGE_ANALYSIS 1.0 preservada como referência histórica |
| `page-analysis-v2.js` | PAGE_ANALYSIS 2.0 usada atualmente |
| `combined-analysis.js` | combinação contextual entre URL e página |
| `reputation.js` | normalização e consulta da reputação |
| `vendor/tldts.umd.min.js` | domínio registrável com Public Suffix List |
| `navigation-policy.js` | compatibilidade de interceptação |
| `navigation-state.js` | TTL e estado das exceções de navegação |
| `content.js` | interceptação de cliques e coleta pós-carregamento |
| `background.js` | reputação, combinação, navegação e exceções |
| `evaluation/` | datasets, protocolos, resultados e artefatos |
| `tests/` | testes de URL, página, reputação, navegação e privacidade |

## Privacidade

A análise de página trabalha com metadados estruturais. Ela não acessa `input.value` nem `textarea.value` e não registra o conteúdo digitado pelo usuário. O snapshot bruto permanece no content script; somente o resultado agregado da análise é enviado ao service worker.

## Instalação local no Edge

1. Abra `edge://extensions`.
2. Ative **Modo do desenvolvedor**.
3. Clique em **Carregar sem compactação**.
4. Selecione a pasta do projeto.
5. Use `test.html` para casos controlados.

## Testes

```bash
npm test
```

A suíte cobre V2, V3, V3.1, PAGE 1.0, PAGE 2.0, combinação, reputação, navegação, privacidade e salvaguardas metodológicas do Dataset C.

## Reprodutibilidade

O repositório preserva versões anteriores do detector, protocolos, hashes, seeds, scripts de avaliação e artefatos derivados. Para a validação independente de C, a referência foi congelada antes da montagem final do conjunto e o detector não participou da seleção das amostras.

O corpus PhreshPhish usado na análise de página não é redistribuído integralmente aqui; a avaliação registra versão/revisão da fonte, seed e SHA-256 do corpus derivado. Os resultados de PAGE_ANALYSIS 2.0 estão marcados explicitamente como desenvolvimento porque o corpus já havia sido examinado.

## Limitações atuais

- a análise de URL ainda perde phishing com poucos sinais lexicais/contextuais;
- a taxa de falso alerta no Dataset C foi 6,33% em um conjunto legítimo propositalmente mais difícil;
- a PAGE_ANALYSIS observa um snapshot estático inicial e não executa JavaScript;
- alterações tardias de SPA, iframes e Shadow DOM permanecem fora do escopo;
- formulários legítimos, integrações externas e identidade textual podem se parecer com sinais de phishing;
- a base de reputação envelhece entre atualizações e não cobre ameaças desconhecidas;
- datasets balanceados não representam a prevalência real de phishing na web.

## Encerramento desta etapa

A etapa técnica atual foi encerrada após a validação do Dataset C, a avaliação quantitativa da camada pós-carregamento e o refinamento contextual PAGE_ANALYSIS 2.0. Não está planejado um novo ciclo de tuning sobre os mesmos conjuntos antes da consolidação científica e da apresentação do projeto.

## Licença e terceiros

O projeto é distribuído sob licença MIT. Fontes de dados e dependências de terceiros são documentadas em [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
