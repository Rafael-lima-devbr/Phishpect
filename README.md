# Phishpect

Extensão experimental para Microsoft Edge que combina **análise local baseada em regras** com uma **base local de reputação** para identificar páginas potencialmente fraudulentas e intervir de acordo com o nível de risco.

**Status:** V4 experimental — detector integrado, com validação independente versionada

<p align="center">
  <img width="62%" alt="Phishpect browser extension interface" src="https://github.com/user-attachments/assets/d88ee44d-ad87-46ec-b604-99d0219cf3d9" />
</p>

## Visão geral

O Phishpect analisa URLs antes ou durante a navegação e acrescenta uma etapa local depois do carregamento:

1. **Análise contextual da URL** — a V4 separa protocolo, hostname, domínio registrável, subdomínios, caminho e query e exige relações ou diversidade de evidências.
2. **Reputação local** — consulta uma base gerada a partir do feed ativo do projeto open source [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database).
3. **Análise estrutural da página** — observa o DOM após `DOMContentLoaded` e novamente 1,2 segundo depois, sem ler o conteúdo digitado pelo usuário.
4. **Fusão contextual** — relaciona identidade, autenticação, infraestrutura, transporte, coleta e destino antes da decisão final.

HTTP, URL longa e termos apenas no caminho permanecem sinais fracos e não geram alerta sozinhos. O domínio registrável é obtido com `tldts` e a Public Suffix List, inclusive para sufixos compostos e privados.

A classificação final pode ser:

| Resultado | Comportamento |
|---|---|
| `safe` | Navegação liberada |
| `suspicious` | Exibe os motivos e permite voltar ou continuar |
| `blocked` | Bloqueia quando há evidência local de alto risco ou correspondência na base de reputação |

A ausência de uma URL na base de reputação **não significa que ela seja segura**.

<p align="center">
  <img width="58%" alt="Phishpect risk classification screen" src="https://github.com/user-attachments/assets/857dbf90-e6a5-45be-89a4-608ac4f4cead" />
</p>

## Fluxo de análise

```text
URL
 ├─> Evidências contextuais locais
 └─> Reputação local
          |
          v
   Decisão inicial integrada
          |
          v
 safe / suspicious / blocked

Página carregada
 └─> Snapshot inicial + snapshot tardio limitado
          |
          v
 Fusão contextual -> decisão final
```

Cliques são avaliados antes de sair da página. Outras navegações, incluindo URLs digitadas na barra, são observadas pelo service worker com `webNavigation.onBeforeNavigate` e redirecionadas para a tela de aviso quando necessário.

<p align="center">
  <img width="58%" alt="Phishpect navigation intervention screen" src="https://github.com/user-attachments/assets/59bca49c-ef6c-48df-9bce-f29b186029a7" />
</p>

A análise pós-carregamento usa duas observações locais e finitas, sem `MutationObserver` contínuo, e não lê valores preenchidos. `blocked` fica reservado a reputação ou ameaça confirmada e evidência crítica corroborada. Links com modificadores, clique do meio, downloads, novos targets e navegação apenas por fragmento mantêm o comportamento nativo. A arquitetura e os resultados estão em [`docs/v4.md`](docs/v4.md).

## Arquitetura

| Arquivo / diretório | Responsabilidade |
|---|---|
| `analysis-v4.js` | Evidências contextuais de URL da V4 |
| `page-analysis-v4.js` | Dupla observação estrutural limitada |
| `combined-analysis-v4.js` | Fusão contextual e classificação final |
| `analysis.js` | Motor V3.1 preservado como referência histórica |
| `analysis-v3.js` | Implementação V3 preservada para comparação |
| `analysis-v2.js` | Implementação V2 preservada para comparação |
| `vendor/tldts.umd.min.js` | Parser de domínio registrável com a Public Suffix List incorporada |
| `reputation.js` | Normalização e consulta da base de reputação |
| `page-analysis.js` / `page-analysis-v2.js` | Implementações históricas preservadas |
| `combined-analysis.js` | Combinação histórica preservada |
| `navigation-policy.js` | Regras testáveis de compatibilidade para interceptação de links |
| `navigation-state.js` | TTL, validação e coordenação das exceções de navegação |
| `content.js` | Interceptação compatível e observações finitas após o carregamento |
| `background.js` | Reputação, combinação de evidências, navegação e controle de exceções |
| `warning.html` / `warning.js` | Interface de aviso e bloqueio |
| `reputation/threat-db.json` | Snapshot local da base de reputação |
| `scripts/` | Atualização da base e avaliação experimental |
| `tests/` | Testes automatizados de V2, V3, V3.1, página, reputação, navegação e privacidade |
| `evaluation/` | Datasets, resultados e registros das execuções |
| `manifest.json` | Configuração da extensão em Manifest V3 |

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

Os testes verificam V2, V3, V3.1, V4 integrada, privacidade, segurança, navegação, estado opaco do aviso e salvaguardas dos datasets. O popup também oferece páginas fictícias em `demo/` para inspeção manual.

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

Na V4, A/B/C e o corpus de páginas conhecido são regressão de desenvolvimento. O Dataset D foi construído somente depois do freeze e executado uma vez como validação independente da decisão inicial integrada (URL + reputação): TP 50, TN 100, FP 0, FN 50, recall 50%, F1 66,67% e FAR 0%. Como o conjunto é balanceado, precision e accuracy não devem ser extrapoladas para a web real. Consulte [`docs/v4.md`](docs/v4.md) e os [artefatos oficiais](evaluation/results/v4/dataset-d/official/metrics.json).

## Evolução

- **V1:** heurísticas locais iniciais e recall muito baixo.
- **V2:** maior recuperação por score, com maior risco de sinais correlacionados inflarem a decisão.
- **V3:** parsing por componentes e política conservadora.
- **V3.1:** diversidade de categorias e relações contextuais, avaliada oficialmente no Dataset C.
- **V4:** primeira versão integrada do pipeline completo: URL, reputação, página, fusão contextual e intervenção pertencem à mesma decisão.

<!-- MEDIA: Quando os resultados finais estiverem consolidados, adicione aqui um gráfico ou tabela-resumo com as métricas principais. -->

## Limitações atuais

- `webNavigation` observa o início da navegação, mas não cancela sincronicamente uma requisição usando lógica JavaScript arbitrária; uma requisição pode começar antes do redirecionamento para o aviso.
- A análise de página observa dois instantes finitos; conteúdo posterior, Shadow DOM e iframes fora do escopo podem escapar.
- Nomes de campos não padronizados, canvas e imagens sem texto alternativo podem ocultar sinais.
- A base de reputação pode conter falsos positivos, envelhece entre atualizações e não cobre ameaças ainda desconhecidas.
- No Dataset D, metade do phishing não apresentou contexto lexical suficiente; shared hosting e HTTP isolados permaneceram deliberadamente insuficientes.
- HTTPS não é tratado como garantia de segurança.
- O Dataset D mede URL + reputação; ainda falta uma nova validação independente para a etapa pós-carregamento.

## Próximos passos

- construir um corpus independente de HTML/snapshots inertes para a V4, sem visitar phishing;
- automatizar e versionar atualizações periódicas da reputação;
- avaliar `declarativeNetRequest` para bloqueio prévio de domínios conhecidos;
- avaliar com um corpus futuro de páginas HTML rotuladas, separado dos datasets de URL.

## Licença e terceiros

O projeto é distribuído sob a licença MIT. Dependências e fontes de dados de terceiros são documentadas em [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
