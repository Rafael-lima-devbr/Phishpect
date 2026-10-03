# Phishpect

Extensão experimental para Microsoft Edge que combina **heurísticas locais** com uma **base local de reputação** para identificar páginas potencialmente fraudulentas e intervir de acordo com o nível de risco.

**Status:** MVP experimental

## Visão geral

O Phishpect analisa URLs antes ou durante a navegação e combina duas fontes de evidência:

1. **Análise heurística local** — avalia sinais como HTTP, endereço IP, Punycode, URLs longas, excesso de subdomínios, `@` e termos sensíveis.
2. **Reputação local** — consulta uma base gerada a partir do feed ativo do projeto open source [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database).

A classificação final pode ser:

| Resultado | Comportamento |
|---|---|
| `safe` | Navegação liberada |
| `suspicious` | Exibe os motivos e permite voltar ou continuar |
| `blocked` | Bloqueia quando há evidência confirmada local ou correspondência na base de reputação |

A ausência de uma URL na base de reputação **não significa que ela seja segura**.

## Fluxo de análise

```text
URL
 ├─> Heurísticas locais
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
| `analysis.js` | Motor heurístico e regras locais de análise |
| `reputation.js` | Normalização e consulta da base de reputação |
| `content.js` | Interceptação de cliques e solicitação da análise |
| `background.js` | Combinação de evidências, navegação e controle de exceções |
| `warning.html` / `warning.js` | Interface de aviso e bloqueio |
| `reputation/threat-db.json` | Snapshot local da base de reputação |
| `scripts/` | Atualização da base e avaliação experimental |
| `tests/` | Testes automatizados das regras locais |
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

Se a base local estiver ausente ou inválida, a extensão continua funcionando somente com a análise heurística.

## Testes

```bash
npm test
```

Os testes automatizados verificam regras locais do motor de análise sem depender da navegação real do navegador.

## Avaliação experimental

O repositório mantém um conjunto independente para comparar a heurística local com o método combinado. A construção do dataset utiliza fontes separadas para phishing e sites legítimos, e a amostra utilizada em cada execução é versionada.

Para reconstruir o dataset com os feeds disponíveis no momento:

```bash
npm run build-evaluation-dataset
```

Para executar a avaliação:

```bash
node scripts/evaluate-dataset.js evaluation/datasets/dataset-a.csv evaluation/results/raw/dataset-a-v1.csv
```

Os resultados registram, entre outros campos:

- `local_score`
- `local_classification`
- `external_listed`
- `external_source`
- `final_classification`

As execuções em `evaluation/runs/` preservam informações como hashes, horário, versão do Node.js e commit avaliado, permitindo relacionar os resultados ao estado exato do projeto.

## Limitações atuais

- `webNavigation` observa o início da navegação, mas não cancela sincronicamente uma requisição usando lógica JavaScript arbitrária; uma requisição pode começar antes do redirecionamento para o aviso.
- O MVP não analisa HTML, formulários ou conteúdo remoto da página.
- A base de reputação pode conter falsos positivos, envelhece entre atualizações e não cobre ameaças ainda desconhecidas.
- Pesos e limiar heurístico permanecem experimentais e precisam de calibração com dados de pesquisa.

## Próximos passos

- calibrar pesos, limiar e taxa de falsos positivos;
- automatizar e versionar atualizações periódicas da reputação;
- avaliar `declarativeNetRequest` para bloqueio prévio de domínios conhecidos;
- estudar sinais do conteúdo da página em uma etapa posterior.

## Licença e terceiros

O projeto é distribuído sob a licença MIT. Dependências e fontes de dados de terceiros são documentadas em [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
