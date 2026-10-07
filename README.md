# Phishpect

Extensão experimental para Microsoft Edge que combina **análise local baseada em regras** com uma **base local de reputação** para identificar páginas potencialmente fraudulentas e intervir de acordo com o nível de risco.

**Status:** MVP experimental

<img width="520" height="472" alt="image" src="https://github.com/user-attachments/assets/d88ee44d-ad87-46ec-b604-99d0219cf3d9" />

<img width="483" height="386" alt="image" src="https://github.com/user-attachments/assets/857dbf90-e6a5-45be-89a4-608ac4f4cead" />

<img width="503" height="313" alt="image" src="https://github.com/user-attachments/assets/59bca49c-ef6c-48df-9bce-f29b186029a7" />




## Visão geral

O Phishpect analisa URLs antes ou durante a navegação e combina duas fontes de evidência:

1. **Análise local baseada em regras** — a V3.1 separa protocolo, hostname, domínio registrável, subdomínios, caminho e query. O score é limitado por categoria e exige identidade forte ou diversidade de evidências.
2. **Reputação local** — consulta uma base gerada a partir do feed ativo do projeto open source [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database).

HTTP, URL longa e termos apenas no caminho permanecem sinais fracos e não geram alerta sozinhos. O domínio registrável é obtido com `tldts` e a Public Suffix List, inclusive para sufixos compostos e privados.

A classificação final pode ser:

| Resultado | Comportamento |
|---|---|
| `safe` | Navegação liberada |
| `suspicious` | Exibe os motivos e permite voltar ou continuar |
| `blocked` | Bloqueia quando há evidência local de alto risco ou correspondência na base de reputação |

A ausência de uma URL na base de reputação **não significa que ela seja segura**.

## Fluxo de análise

```text
URL
 ├─> Análise local
 └─> Reputação local
          |
          v
   Combinação de evidências
          |
          v
 safe / suspicious / blocked
```

Cliques são avaliados antes de sair da página. Outras navegações, incluindo URLs digitadas na barra, são observadas pelo service worker com `webNavigation.onBeforeNavigate` e redirecionadas para a tela de aviso quando necessário.

## Arquitetura

| Arquivo / diretório | Responsabilidade |
|---|---|
| `analysis.js` | Motor de análise V3.1 usado pela extensão |
| `analysis-v3.js` | Implementação V3 preservada para comparação |
| `analysis-v2.js` | Implementação V2 preservada para comparação |
| `vendor/tldts.umd.min.js` | Parser de domínio registrável com a Public Suffix List incorporada |
| `reputation.js` | Normalização e consulta da base de reputação |
| `content.js` | Interceptação de cliques e solicitação da análise |
| `background.js` | Combinação de evidências, navegação e controle de exceções |
| `warning.html` / `warning.js` | Interface de aviso e bloqueio |
| `reputation/threat-db.json` | Snapshot local da base de reputação |
| `scripts/` | Atualização da base e avaliação experimental |
| `tests/` | Testes automatizados das regras V2, V3 e V3.1 |
| `evaluation/` | Datasets, resultados e registros das execuções |
| `manifest.json` | Configuração da extensão em Manifest V3 |

<!-- MEDIA: Se quiser usar um diagrama visual de arquitetura no futuro, coloque-o aqui, logo após a tabela de arquitetura. -->

## Instalação local no Edge

1. Abra `edge://extensions`.
2. Ative **Modo do desenvolvedor**.
3. Clique em **Carregar sem compactação**.
4. Selecione a pasta deste projeto.
5. Use `test.html` ou navegação controlada para testar os diferentes resultados.

Ao atualizar o código, use **Recarregar** no cartão da extensão.

## Atualização da base de reputação

Com Node.js instalado:

```bash
npm run update-threat-db
```

O processo baixa o feed configurado, normaliza as entradas, remove duplicatas e gera o snapshot utilizado pela extensão. O script não abre nem testa as URLs contidas no feed.

Se a base local estiver ausente ou inválida, a extensão continua funcionando somente com a análise local.

## Testes

```bash
npm test
```

Os testes automatizados verificam V2, V3 e V3.1 sem depender da navegação real do navegador.

## Avaliação experimental

O repositório mantém conjuntos versionados para comparar as versões do analisador.

Para reconstruir um dataset com os feeds disponíveis no momento:

```bash
npm run build-evaluation-dataset
```

Para executar explicitamente cada versão:

```bash
node scripts/evaluate-dataset.js --analyzer=v2 evaluation/datasets/dataset-a.csv evaluation/results/refinement/dataset-a-v2.csv
node scripts/evaluate-dataset.js --analyzer=v3 evaluation/datasets/dataset-a.csv evaluation/results/refinement/dataset-a-v3.csv
node scripts/evaluate-dataset.js --analyzer=v3.1 evaluation/datasets/dataset-a.csv evaluation/results/refinement/dataset-a-v3-1.csv
```

Os resultados registram score, classificação, reasons, contribuições, scores por categoria, diversidade, sinais, características, reputação e classificação final. O terminal apresenta TP, FN, FP, TN, recall, precision, F1, taxa de falso alerta e acurácia.

As execuções e os resultados versionados permitem relacionar as métricas ao estado exato do projeto. Como os Datasets A e B foram consultados durante a calibração da V3 e V3.1, ambos são dados de desenvolvimento e não constituem validação independente. Um futuro Dataset C deve ser coletado depois do congelamento das regras e permanecer reservado até a avaliação final.

<!-- MEDIA: Quando os resultados finais estiverem consolidados, adicione aqui um gráfico ou tabela-resumo com as métricas principais. -->

## Limitações atuais

- `webNavigation` observa o início da navegação, mas não cancela sincronicamente uma requisição usando lógica JavaScript arbitrária; uma requisição pode começar antes do redirecionamento para o aviso.
- O MVP não analisa HTML, formulários ou conteúdo remoto da página.
- A base de reputação pode conter falsos positivos, envelhece entre atualizações e não cobre ameaças ainda desconhecidas.
- A V3.1 recupera recall por diversidade de categorias, mas ainda perde páginas de phishing sem sinais lexicais suficientes.
- HTTPS não é tratado como garantia de segurança.
- Os pesos e o limiar da análise local permanecem experimentais até validação com dados novos.

## Próximos passos

- congelar a V3.1 e construir um Dataset C temporalmente posterior, com páginas legítimas difíceis e phishing novo;
- automatizar e versionar atualizações periódicas da reputação;
- avaliar `declarativeNetRequest` para bloqueio prévio de domínios conhecidos;
- estudar sinais do conteúdo da página em uma etapa posterior.

## Licença e terceiros

O projeto é distribuído sob a licença MIT. Dependências e fontes de dados de terceiros são documentadas em [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
