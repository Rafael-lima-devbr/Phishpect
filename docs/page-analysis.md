# Análise pós-carregamento — PAGE_ANALYSIS 2.0

## Estado

A versão atualmente carregada pela extensão é a **PAGE_ANALYSIS 2.0** (`page-analysis-v2.js`). A implementação anterior foi preservada em `page-analysis.js` porque participou da primeira avaliação quantitativa independente da camada pós-carregamento.

A versão 2.0 foi desenvolvida **depois** da inspeção dos erros dessa avaliação. Por isso, qualquer métrica da 2.0 no mesmo corpus é resultado de desenvolvimento e não deve ser apresentada como validação independente.

## Objetivo

A camada pós-carregamento complementa a V3.1 com informações estruturais disponíveis após `DOMContentLoaded`. Ela é local, determinística, baseada em regras e nunca gera `blocked` sozinha.

Os resultados permanecem separados:

- `URL_ANALYSIS`: V3.1 + reputação local;
- `PAGE_ANALYSIS`: estrutura e contexto da página;
- `COMBINED_ANALYSIS`: decisão final contextual.

## Privacidade

A coleta usa somente metadados necessários à análise, incluindo:

- título e identidade textual limitada;
- cabeçalhos e textos associados a formulários;
- atributo `alt` de imagens em contexto;
- método e `action` de formulários;
- `type`, `name`, `id`, `autocomplete`, `placeholder` e `aria-label` dos campos.

O código **não acessa valores digitados** em `input` ou `textarea`. O snapshot bruto permanece no content script e somente o resultado agregado da análise é enviado ao service worker.

## O que mudou em relação à PAGE_ANALYSIS 1.0

A primeira versão conseguia somar sinais encontrados em regiões diferentes da página. Na avaliação com PhreshPhish isso produziu dois falsos positivos: menções incidentais a Instagram e Google em elementos sociais/aplicativos foram combinadas com formulários legítimos.

A 2.0 introduziu três mudanças principais:

1. **Identidade contextual** — rodapés, `nav`, `aside`, links sociais e badges de lojas deixam de representar automaticamente a identidade principal. Título, cabeçalhos de autenticação, logos relevantes e identidade próxima ao formulário recebem maior peso contextual.
2. **Localização das evidências** — campos, destino e identidade são avaliados por formulário ou grupo estrutural coerente. Sinais de partes independentes da página não são somados como se pertencessem à mesma coleta.
3. **Campos fora de `form`** — podem ser agrupados por contêiner estrutural, evitando combinar artificialmente email e senha pertencentes a áreas diferentes.

A identificação de campos também usa `placeholder` e `aria-label`, mantendo a restrição de não ler valores.

## Categorias e limiar

Os tetos permanecem:

| Categoria | Teto |
|---|---:|
| credenciais | 10 |
| dados sensíveis | 12 |
| destino do formulário | 14 |
| identidade | 12 |
| estrutura da página | 6 |

O limiar da PAGE_ANALYSIS continua em **18**. Duas categorias relacionadas recebem bônus de diversidade 6; três ou mais recebem 10.

A classificação `suspicious` exige, além do score, uma combinação contextual, como:

- senha/credenciais enviadas para domínio externo;
- cartão, documento ou dados bancários enviados externamente;
- senha em página HTTP;
- downgrade HTTPS → HTTP com coleta relevante;
- identidade incompatível com o domínio ligada a coleta de credenciais ou dados sensíveis.

Telefone/endereço externos isolados, login normal, shared hosting isolado e menções de marcas sem contexto não são suficientes.

## Public Suffix List

`tldts` é usado com suporte a sufixos públicos e privados para calcular domínio registrável. Isso permite comparar corretamente a página e o destino de formulários em estruturas como `com.br`, `co.uk` e hospedagens com sufixos privados.

## Integração

`combined-analysis.js` foi mantido inalterado durante o refinamento 2.0. Ele:

- preserva qualquer `blocked` vindo de evidência mais forte;
- preserva URL já `suspicious`;
- aceita PAGE `suspicious`;
- possui combinações adicionais entre identidade da URL e coleta de dados;
- não soma cegamente os scores das camadas.

O indicador exibido é heurístico e não representa probabilidade de fraude.

## Execução

A coleta ocorre uma única vez após `DOMContentLoaded`.

Nesta etapa não há:

- `MutationObserver`;
- execução de JavaScript de páginas do corpus;
- inspeção de iframes;
- travessia de Shadow DOM;
- análise visual por screenshot/canvas.

## Avaliação quantitativa da versão 1.0

A primeira avaliação independente utilizou 240 pares URL–HTML do PhreshPhish v1.0.1:

| Modo | TP | TN | FP | FN | Recall | F1 | FAR |
|---|---:|---:|---:|---:|---:|---:|---:|
| URL-only | 4 | 120 | 0 | 116 | 3,33% | 6,45% | 0% |
| PAGE 1.0 | 2 | 118 | 2 | 118 | 1,67% | 3,23% | 1,67% |
| COMBINED 1.0 | 6 | 118 | 2 | 114 | 5,00% | 9,38% | 1,67% |

A combinação recuperou dois phishing e introduziu dois falsos positivos. O ganho de recall e o aumento de FAR foram ambos de 1,67 ponto percentual.

## Comparação de desenvolvimento da 2.0

Depois da inspeção dos erros, o mesmo corpus passou a ser dado de desenvolvimento.

| Modo | TP | TN | FP | FN | Recall | Precision | F1 | FAR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PAGE 2.0 | 1 | 120 | 0 | 119 | 0,83% | 100% | 1,65% | 0% |
| COMBINED + PAGE 2.0 | 5 | 120 | 0 | 115 | 4,17% | 100% | 8,00% | 0% |

A 2.0 removeu os dois falsos positivos anteriores e não introduziu novos, mas perdeu um verdadeiro positivo. O caso perdido dependia de uma associação global entre uma referência social a Instagram e campos localizados em outro bloco da página, comportamento que foi deliberadamente removido por ser conceitualmente frágil.

O resultado é interpretado como **melhora de coerência contextual**, não como demonstração de aumento de eficácia. Continuar ajustando sobre o mesmo corpus elevaria o risco de overfitting.

Artefatos: [`evaluation/results/page-analysis/development-v2/`](../evaluation/results/page-analysis/development-v2/) e [resumo da avaliação](../evaluation/results/page-analysis/README.md).

## Limitações

- 79/120 páginas de phishing do corpus não possuíam elemento `form`;
- 82/120 não apresentavam campos na projeção estática;
- scripts e iframes são frequentes tanto em legítimas quanto em phishing e não podem ser usados isoladamente como sinal;
- conteúdo criado depois do snapshot pode não ser observado;
- identidade visual não textual permanece fora do escopo;
- provedores legítimos de SSO, CRM, pagamento e formulários externos continuam sendo casos difíceis.

A etapa técnica atual foi encerrada sem novo ciclo de tuning.
