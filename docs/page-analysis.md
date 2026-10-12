# Análise pós-carregamento

## Objetivo e escopo

A camada pós-carregamento complementa a análise de URL V3.1 com evidências estruturais disponíveis depois de `DOMContentLoaded`. Ela é local, determinística e baseada em regras. Não substitui a V3.1 nem a reputação, não consulta serviços externos e nunca produz a classificação `blocked`.

Os três resultados permanecem separados:

- `URL_ANALYSIS`: V3.1 e reputação local, calculadas pelo service worker;
- `PAGE_ANALYSIS`: formulários, tipos de campos, destino dos formulários e identidade visual textual limitada;
- `COMBINED_ANALYSIS`: decisão contextual sem somar cegamente todos os pontos.

`blocked` continua reservado para ameaça confirmada pela lista local de testes ou pela base de reputação. A página pode apenas manter o resultado ou elevá-lo para `suspicious`.

## Fluxo de dados

1. `content.js` intercepta apenas cliques primários comuns destinados à aba atual desde `document_start`. Links com modificadores, clique do meio, `download`, `_blank`, targets nomeados e mudanças apenas de fragmento preservam o comportamento nativo.
2. Depois de `DOMContentLoaded`, ele executa a coleta uma única vez.
3. `collectPageSnapshot` cria um snapshot limitado da estrutura do documento.
4. `analyzePage` converte esse snapshot em sinais, categorias, score e motivos explicáveis.
5. Somente o resultado agregado de `PAGE_ANALYSIS` é enviado ao service worker.
6. `background.js` recalcula a URL, combina as duas camadas e abre o aviso apenas quando a página acrescenta risco contextual.

Não há `MutationObserver` nesta etapa. A análise ocorre exatamente uma vez depois de `DOMContentLoaded`; aplicações SPA que criarem ou alterarem formulários depois da análise inicial podem não ser cobertas.

## Garantia de privacidade

A coleta lê somente:

- título do documento;
- texto de `h1` e `h2`;
- atributo `alt` de imagens;
- método e atributo `action` dos formulários;
- tag, `type`, `name`, `id` e `autocomplete` dos campos.

O conteúdo preenchido em `input` ou `textarea` nunca é acessado, armazenado ou enviado. Os testes usam um campo cujo acesso ao conteúdo digitado lança uma exceção; a coleta precisa terminar normalmente para o teste passar. O snapshot bruto também não é enviado ao service worker: apenas contagens, booleanos, categorias, destinos normalizados e motivos. Logs internos são genéricos e não incluem URLs completas, conteúdo do DOM nem dados digitados.

Para limitar custo e exposição, são inspecionados no máximo 30 formulários, 80 campos por formulário, 12 títulos e 20 textos alternativos. Textos coletados são truncados.

## Domínios e destinos de formulário

`page-analysis.js` resolve `action` ausente, relativa e absoluta com `URL`. O domínio registrável é calculado por `tldts` com a Public Suffix List e suporte a sufixos privados, como na V3.1.

São registrados:

- método `GET`, `POST`, `DIALOG` ou `OTHER` (com o método original limitado, quando não reconhecido);
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
- cartão, documento ou dado bancário com destino externo;
- senha em página HTTP;
- marca fora do domínio oficial combinada com senha ou dados sensíveis;
- downgrade HTTPS → HTTP combinado com coleta relevante.

Assim, senha isolada, formulário externo isolado, telefone/endereço externo isolado, artigo que menciona uma marca e login legítimo no mesmo domínio não geram alerta sozinhos. Senha externa e cartão externo mantêm o comportamento anterior.

Os campos são reconhecidos por tokens controlados derivados de `name`, `id`, `type` e `autocomplete`, com separação de `camelCase` e delimitadores. Não é usado substring matching amplo: por exemplo, `documentation` não vira documento, `discard` não vira cartão e `accountNumber` não vira usuário.

## Combinação com a URL

`combined-analysis.js` conserva `blocked`, mantém qualquer URL já `suspicious` e aceita `PAGE_ANALYSIS=suspicious`. Também há duas combinações entre camadas:

- contexto forte de identidade na URL + coleta de credenciais ou dados sensíveis;
- infraestrutura/autenticação na URL, uma segunda categoria independente de evidência e formulário completo de identificação e senha.

Uma única categoria de autenticação em subdomínio ou uma única categoria de shared hosting não eleva um login normal por si só. A evidência de marca exata fora do domínio oficial continua com o mesmo score e motivo na URL, mas precisa de contexto adicional para tornar o endereço `suspicious`.

O indicador heurístico combinado exibido é o maior score das camadas, não a soma, não é uma probabilidade e não deve ser interpretado como porcentagem de fraude. Os motivos recebem os prefixos `[URL]`, `[Página]` e `[Combinação]`. Objetos de análise recebidos são normalizados antes da combinação; níveis, scores, motivos e sinais inválidos não podem elevar o risco.

Ao escolher “Continuar mesmo assim”, a exceção temporária dura no máximo 60 segundos e também suprime o alerta pós-carregamento daquela mesma carga, evitando um segundo aviso imediato. Ela é consumida uma vez, expira e é limpa em navegações incompatíveis ou no fechamento da aba. A origem da mensagem é validada como a página de aviso da extensão. A permissão continua válida somente para URL `suspicious`; `blocked` permanece sem exceção.

A reputação distingue base disponível com URL não listada de base indisponível. Em falhas internas de análise, a navegação original é restaurada (fail-open), enquanto a política de `blocked` permanece inalterada quando a reputação está disponível.

## Testes e demonstrações

Execute:

```bash
npm test
```

Para uma medição simples e reproduzível do custo das três camadas com URLs reservadas para documentação, execute `npm run benchmark`. O resultado informa tempo total e média por iteração; não é um limite de desempenho nem substitui profiling no navegador.

Os testes cobrem página segura, login legítimo, tokenização, preservação de métodos, telefone/endereço externos, senha e cartão externos, marca contextual, validação dos objetos combinados, reputação disponível/indisponível, isolamento de tenants, TTL, origem da continuação, corridas de redirecionamento, fragmentos e comportamentos nativos de links. A garantia de privacidade usa campos cujo acesso ao conteúdo digitado lança uma exceção.

O popup `test.html` liga para cinco páginas fictícias em `demo/`. Cada página usa uma URL sintética em metadado, impede o envio do formulário e mostra o `PAGE_ANALYSIS` completo. Os domínios `example.com` e `example.net` são usados apenas como exemplos reservados.

Os Datasets A e B continuam avaliando exclusivamente URLs. Eles não medem esta camada porque não contêm HTML versionado nem rótulos de comportamento da página.

## Limitações

- A análise inicial não acompanha alterações tardias de SPA.
- Iframes não são analisados (`all_frames` permanece desativado) e Shadow DOM não é percorrido.
- Campos fora de formulários não entram na coleta estrutural atual.
- Nomes de campos não padronizados podem ocultar o tipo de dado solicitado.
- Conteúdo visual renderizado em canvas, imagens sem `alt` e textos fora dos elementos limitados não são interpretados.
- Formulários legítimos podem usar processadores externos, provedores SSO e gateways; combinações de senha, cartão ou outros sinais fortes com esses destinos ainda podem gerar falso alerta.
- A lista de marcas é explícita e limitada.
- Páginas podem mudar depois da coleta inicial.
