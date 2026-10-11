# Análise pós-carregamento

## Objetivo e escopo

A camada pós-carregamento complementa a análise de URL V3.1 com evidências estruturais disponíveis depois de `DOMContentLoaded`. Ela é local, determinística e baseada em regras. Não substitui a V3.1 nem a reputação, não consulta serviços externos e nunca produz a classificação `blocked`.

Os três resultados permanecem separados:

- `URL_ANALYSIS`: V3.1 e reputação local, calculadas pelo service worker;
- `PAGE_ANALYSIS`: formulários, tipos de campos, destino dos formulários e identidade visual textual limitada;
- `COMBINED_ANALYSIS`: decisão contextual sem somar cegamente todos os pontos.

`blocked` continua reservado para ameaça confirmada pela lista local de testes ou pela base de reputação. A página pode apenas manter o resultado ou elevá-lo para `suspicious`.

## Fluxo de dados

1. `content.js` continua interceptando links desde `document_start`.
2. Depois de `DOMContentLoaded`, ele executa a coleta uma única vez.
3. `collectPageSnapshot` cria um snapshot limitado da estrutura do documento.
4. `analyzePage` converte esse snapshot em sinais, categorias, score e motivos explicáveis.
5. Somente o resultado agregado de `PAGE_ANALYSIS` é enviado ao service worker.
6. `background.js` recalcula a URL, combina as duas camadas e abre o aviso apenas quando a página acrescenta risco contextual.

Não há `MutationObserver` nesta etapa. Aplicações SPA que criarem formulários depois da análise inicial podem não ser cobertas.

## Garantia de privacidade

A coleta lê somente:

- título do documento;
- texto de `h1` e `h2`;
- atributo `alt` de imagens;
- método e atributo `action` dos formulários;
- tag, `type`, `name`, `id` e `autocomplete` dos campos.

O conteúdo preenchido em `input` ou `textarea` nunca é acessado, armazenado ou enviado. Os testes usam um campo cujo acesso ao conteúdo digitado lança uma exceção; a coleta precisa terminar normalmente para o teste passar. O snapshot bruto também não é enviado ao service worker: apenas contagens, booleanos, categorias, destinos normalizados e motivos.

Para limitar custo e exposição, são inspecionados no máximo 30 formulários, 80 campos por formulário, 12 títulos e 20 textos alternativos. Textos coletados são truncados.

## Domínios e destinos de formulário

`page-analysis.js` resolve `action` ausente, relativa e absoluta com `URL`. O domínio registrável é calculado por `tldts` com a Public Suffix List e suporte a sufixos privados, como na V3.1.

São registrados:

- método `GET` ou `POST`;
- destino ausente, relativo ou absoluto;
- protocolo e domínio registrável do destino;
- envio para outro domínio registrável;
- downgrade de página HTTPS para ação HTTP.

Um destino externo isolado não basta para alertar.

## Categorias e tetos

| Categoria | Exemplos | Teto |
| --- | --- | ---: |
| Credenciais | senha, identificador, conjunto identificador + senha | 10 |
| Dados sensíveis | cartão, telefone, documento, banco/Pix e endereço | 12 |
| Destino do formulário | domínio externo, downgrade e credenciais em HTTP | 14 |
| Identidade | marca conhecida fora do domínio oficial em contexto de coleta | 12 |
| Estrutura da página | muitos formulários ou formulário muito grande | 6 |

O threshold da página é 18. Duas categorias recebem bônus de diversidade 6; três ou mais recebem 10. Além do score, é obrigatória uma combinação contextual:

- senha ou credenciais com destino externo;
- dados sensíveis com destino externo;
- senha em página HTTP;
- marca fora do domínio oficial combinada com senha ou dados sensíveis;
- downgrade HTTPS → HTTP combinado com coleta relevante.

Assim, senha isolada, formulário externo isolado, artigo que menciona uma marca e login legítimo no mesmo domínio não geram alerta sozinhos.

## Combinação com a URL

`combined-analysis.js` conserva `blocked`, mantém qualquer URL já `suspicious` e aceita `PAGE_ANALYSIS=suspicious`. Também há duas combinações entre camadas:

- contexto forte de identidade na URL + coleta de credenciais ou dados sensíveis;
- infraestrutura/autenticação suspeita na URL + formulário completo de identificação e senha.

O score combinado exibido é o maior score das camadas, não a soma. Os motivos recebem os prefixos `[URL]`, `[Página]` e `[Combinação]`.

Ao escolher “Continuar mesmo assim”, a exceção de uma navegação também suprime o alerta pós-carregamento daquela mesma carga, evitando um segundo aviso imediato. A permissão continua válida somente para URL `suspicious`; `blocked` permanece sem exceção.

## Testes e demonstrações

Execute:

```bash
npm test
```

Os testes de página cobrem página segura, login legítimo, senha isolada, formulário externo isolado, HTTP + senha, credenciais externas, marca contextual, domínio oficial, dados de cartão externos, PSL e a garantia de não leitura do conteúdo digitado.

O popup `test.html` liga para cinco páginas fictícias em `demo/`. Cada página usa uma URL sintética em metadado, impede o envio do formulário e mostra o `PAGE_ANALYSIS` completo. Os domínios `example.com` e `example.net` são usados apenas como exemplos reservados.

Os Datasets A e B continuam avaliando exclusivamente URLs. Eles não medem esta camada porque não contêm HTML versionado nem rótulos de comportamento da página.

## Limitações

- A análise inicial não acompanha alterações tardias de SPA.
- Nomes de campos não padronizados podem ocultar o tipo de dado solicitado.
- Conteúdo visual renderizado em canvas, imagens sem `alt` e textos fora dos elementos limitados não são interpretados.
- Formulários legítimos podem usar processadores externos; por isso o destino externo exige coleta relevante e score/diversidade.
- A lista de marcas é explícita e limitada.
- Páginas podem mudar depois da coleta inicial.
