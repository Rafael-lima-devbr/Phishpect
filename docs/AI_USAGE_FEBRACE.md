# Transparência sobre uso de IA generativa — FEBRACE 2027

Este registro documenta o uso de ferramentas de IA generativa no desenvolvimento do Phishpect para fins de transparência e rastreabilidade metodológica.

## Ferramentas utilizadas

- **ChatGPT (OpenAI):** discussão técnica, revisão e organização de ideias, apoio metodológico, análise de resultados, revisão documental e apoio na produção de recursos visuais.
- **Codex (OpenAI):** apoio à programação e depuração, edição de arquivos sob instrução, execução de comandos e suítes automatizadas, geração de scripts auxiliares e produção de artefatos de avaliação.

As ferramentas não tiveram autoridade autônoma para definir o problema de pesquisa, os objetivos, a arquitetura final, as fontes de dados, os critérios experimentais, as regras finais do detector, a interpretação científica ou as conclusões. Essas decisões permaneceram sob responsabilidade do estudante autor.

## Partes do código com assistência de IA conhecida

A evolução V4.1 foi realizada com assistência explícita de IA e está preservada no histórico de cinco commits entre a referência V4 `1f9e01d5d17a68e0e3c8dbf435d1c3f424d80e4b` e a referência V4.1 `507d01ce0b56d10f4bfd7ad88e63be09def621bb`.

Arquivos de implementação com assistência conhecida nessa etapa:

- `analysis-v41.js`
- `background-v41.js`
- `combined-analysis-v41.js`
- `content-v41.js`

Scripts e testes produzidos ou modificados com assistência conhecida:

- `scripts/v4.1/analyze-development-errors.js`
- `scripts/v4.1/benchmark-v41.js`
- `scripts/v4.1/evaluate-development.js`
- `tests/analysis-v41.test.js`
- `tests/combined-analysis-v41.test.js`
- `tests/runtime-v41.test.js`
- ajustes relacionados em testes de privacidade

A documentação e os artefatos de desenvolvimento da V4.1 também receberam assistência de IA.

Versões anteriores do projeto receberam sugestões, revisões e apoio de programação em diferentes momentos, mas não foi preservado um registro contemporâneo suficientemente preciso para reconstruir uma atribuição linha a linha de todo o histórico. Por integridade, este documento **não inventa atribuições retroativas**.

## Registro resumido de instruções e respostas

| Tema | Resumo da instrução fornecida | Resumo da resposta e utilização |
| --- | --- | --- |
| Análise de erros da V4.1 | Analisar falsos negativos e falsos positivos e propor relações contextuais generalizáveis sem simplesmente reduzir o limiar global. | A IA sugeriu relações candidatas. Elas foram implementadas/testadas em iterações; o estudante aceitou ou rejeitou mudanças conforme regressões e coerência conceitual. |
| Testes e avaliação | Executar suítes e avaliações nos Datasets A/B/C/D e no corpus HTML e comparar V4 e V4.1. | Codex executou comandos e scripts e produziu artefatos. O estudante conferiu métricas, hashes e a distinção entre validação independente e resultados de desenvolvimento. |
| Segurança e privacidade | Revisar navegação, tokens opacos, exceções temporárias, validação de mensagens, privacidade e comportamento fail-open. | A IA apontou riscos e alternativas; o estudante decidiu as alterações e verificou o comportamento pelos testes automatizados. |
| Redação e documentação | Organizar/revisar clareza e coerência de conteúdo técnico já discutido e, em versões intermediárias, produzir rascunhos de apoio. | Rascunhos de IA foram tratados como material intermediário. Eles não constituem autoria do estudante e não devem ser reproduzidos como tal na versão submetida. |
| Recursos visuais | Representar a arquitetura integrada do Phishpect, mostrando análise de URL, reputação local, análise da página e os níveis de intervenção safe, suspicious e blocked. | O diagrama de arquitetura foi produzido com apoio do ChatGPT e identificado no artigo com ferramenta, prompt resumido e data. O gráfico histórico foi elaborado no Excel pelo estudante. |

## Resultados experimentais

A IA não foi utilizada para inventar, estimar ou alterar métricas. Os resultados apresentados no projeto são derivados de datasets, CSV/JSON, hashes, snapshots e testes versionados no repositório. Quando Codex executou comandos ou suítes, a execução ocorreu sob instrução e os resultados considerados foram conferidos contra os artefatos reais.

## Recursos visuais

As capturas de tela do protótipo são registros reais do software em funcionamento. O diagrama da arquitetura presente na versão preparada em 28/10/2026 foi produzido com apoio do ChatGPT a partir da arquitetura implementada e revisada pelo estudante; o artigo identifica essa assistência. O gráfico histórico de recall e acurácia foi elaborado no Excel pelo estudante a partir das métricas experimentais do projeto e é identificado como autoria própria.

## Redação científica

Ferramentas de IA foram usadas para revisão, reorganização e também para rascunhos intermediários durante o processo de documentação. Esses rascunhos são material de apoio e não substituem a autoria do estudante. A versão submetida à FEBRACE deve ser reescrita e validada pelo estudante quando houver redação substancial inicialmente produzida pela IA.

## Registros complementares

A utilização de IA também é documentada:

- no anexo ao **Formulário 2A**;
- no **diário de bordo**;
- na metodologia do artigo/plano de pesquisa;
- no histórico Git e nos artefatos de avaliação deste repositório.

Registro consolidado em **28 de outubro de 2026**.
