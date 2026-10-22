# Auditoria técnica prévia — Phishpect V4

Data da auditoria: 2026-10-22 (America/Bahia).

Status: concluída antes da implementação da V4. Os arquivos históricos V1, V2,
V3, V3.1, PAGE_ANALYSIS 1.0 e 2.0 e seus resultados permanecem imutáveis.

## Escopo e baseline

A auditoria revisou os motores de URL e página, reputação, fusão, runtime,
navegação, página de aviso, permissões, testes, protocolos e resultados
históricos. A suíte anterior à V4 passou integralmente.

Baseline relevante:

- Dataset C (V3.1, validação então independente): TP 207, TN 281, FP 19,
  FN 93, recall 69,00%, precisão 91,59%, F1 78,71%, acurácia 81,33% e
  FAR 6,33%;
- corpus de páginas conhecido (120/120): URL-only TP 4/FP 0,
  PAGE_ANALYSIS 1.0 TP 2/FP 2 e combinação TP 6/FP 2;
- PAGE_ANALYSIS 2.0 em desenvolvimento removeu os dois FP, mas terminou com
  TP 1/FP 0; a combinação terminou com TP 5/FP 0;
- 79/120 páginas phishing não continham `form`, 82/120 não continham campos
  detectáveis, 100/120 continham scripts e 31/120 continham iframe. Portanto,
  o gargalo principal é observabilidade, não apenas peso ou threshold.

Datasets A, B e C e o corpus conhecido passam a ser desenvolvimento/regressão
para a V4. Nenhum deles poderá sustentar uma alegação de validação independente
da V4.

## Arquitetura atual

O runtime usa quatro decisões parcialmente separadas:

1. V3.1 analisa a URL;
2. a reputação pode substituir o resultado por `blocked`;
3. PAGE_ANALYSIS 2.0 analisa um snapshot único após `DOMContentLoaded`;
4. `combined-analysis.js` preserva o resultado da URL, aceita uma página já
   `suspicious` e possui somente duas combinações entre camadas.

O score final é o máximo entre URL e página. Isso evita somas artificiais, mas
não representa a coerência de uma evidência que atravessa identidade, coleta,
destino e reputação. A reputação também não participa de um modelo explicável
unificado.

## Achados da análise de URL

### Pontos sólidos

- parsing com `URL` e `tldts`, incluindo sufixos privados;
- separação de hostname, domínio registrável, subdomínio, path e query;
- caps por categoria e diversidade;
- HTTP, path longo, URL longa e termo de autenticação no path não alertam
  isoladamente;
- shared hosting não é, sozinho, evidência suficiente;
- V2 e V3 permanecem reproduzíveis em módulos separados.

### Riscos de falso positivo

- Punycode recebe evidência de identidade mesmo sem imitação observável;
- entropia e hífens podem descrever tenants legítimos e nomes pessoais;
- termos como `account`, `secure`, OAuth e SSO aparecem legitimamente em
  hostnames e páginas internas;
- marca no path pode ser documentação, integração, marketplace ou callback;
- URLs longas e queries extensas são comuns em OAuth, SSO, checkout e CRM;
- shared hosting combinado somente com estrutura lexical correlata ainda pode
  elevar páginas legítimas;
- aparições de marca em ccTLD ou domínios compostos exigem decisão pelo domínio
  registrável, nunca por substring.

### Riscos de falso negativo e parsing

- nested URLs e parâmetros de redirect/callback não são modelados como relação;
- portas incomuns não são explicadas;
- múltiplos `@`, userinfo codificado e spoofing por URL aninhada merecem sinais
  explícitos;
- IPv4 é reconhecido por forma, mas os octetos não são validados separadamente;
- IPv6 depende do parser e precisa de cobertura, inclusive com porta;
- Unicode convertido para Punycode pelo parser não recebe contexto de marca;
- marca em query e identidade de redirect não têm relação contextual;
- sinais de estrutura correlatos podem inflar diversidade aparente sem fornecer
  uma segunda família causal.

## Achados da análise pós-carregamento

### Pontos sólidos

- não acessa `input.value` nem `textarea.value`;
- tokenização controlada substituiu substring matching amplo;
- preserva método de formulário e distingue action relativa, absoluta e ausente;
- agrupa campos e identidade por formulário/container;
- reduz peso de footer, navegação, redes sociais e badges de lojas;
- marca incompatível isolada e telefone/endereço externo isolados não alertam.

### Limitações e falsos negativos

- somente um instante após `DOMContentLoaded` é observado;
- DOM inserido logo depois por JavaScript é perdido;
- iframes, Shadow DOM, canvas e texto em imagem não são observados;
- formulários enviados exclusivamente por JavaScript podem não expor `action`;
- páginas sem formulário/campo observável não oferecem evidência estrutural
  suficiente; aumentar pesos não resolve essa ausência;
- o snapshot não registra metadados agregados úteis e baratos, como quantidade
  limitada de iframes, scripts ou meta refresh, embora esses sinais devam ser
  apenas contextuais e nunca decisivos isoladamente.

### Riscos de falso positivo e performance

- login, checkout, newsletter, CRM, OAuth e SSO legítimos contêm campos e forms
  externos normais;
- processadores de pagamento e provedores de identidade criam destinos externos
  legítimos;
- identidade textual pode ser citação, parceiro ou método de pagamento;
- limites de 30 forms e 80 campos protegem custo, mas a coleta repetida precisa
  continuar estritamente limitada;
- observação contínua por MutationObserver teria custo e superfície de privacidade
  desnecessários. A V4 deve usar duas capturas finitas.

## Achados da fusão e reputação

- `combined-analysis.js` é seguro contra objetos malformados, mas modela poucas
  relações entre camadas;
- score final por `max()` não comunica a força da combinação;
- `blocked` é corretamente preservado e não nasce da página atual;
- reputação distingue indisponível de não listado, e “não listado” não é seguro;
- normalização remove fragmento, `www`, trailing slash e ordena query;
- correspondência de domínio é exata; não deve ser ampliada automaticamente a
  domínio pai/filho sem regra explícita;
- faltam métricas dedicadas de carregamento, lookup, memória e tamanho da base;
- o resultado final deve apresentar URL, página e reputação como grupos internos
  de uma única decisão V4.

## Runtime, navegação e UX

### Compatibilidade já protegida

- Ctrl/Meta/Shift/Alt, middle click, `_blank`, targets nomeados, download e
  fragmento da mesma página mantêm comportamento nativo;
- bypass é exato, consumível e possui TTL de 60 segundos;
- origem de `continue-navigation` é validada;
- falha complementar de página não impede navegação.

### Problemas e riscos

- URL completa e motivos ficam na query de `warning.html`, aumentando exposição
  em histórico e diagnósticos internos;
- mensagens pós-carregamento precisam validar fase, URL, aba e formato V4;
- `sender.tab.id === 0` é tratado como ausente por teste de truthiness;
- duas observações podem produzir avisos duplicados se não houver coordenação;
- redirects rápidos, fechamento de aba e reinício do service worker exigem estado
  idempotente e limpeza;
- `webNavigation.onBeforeNavigate` não cancela sincronicamente a requisição;
  essa limitação arquitetural deve continuar explícita;
- páginas SPA que mudam rota depois das duas capturas permanecem parcialmente
  observadas.

## Segurança da extensão

- Manifest V3 e scripts empacotados evitam código remoto;
- `warning.js` usa `textContent`, reduzindo risco de XSS;
- não há `innerHTML` com dados não confiáveis nem telemetria externa;
- `host_permissions` cobrem toda a web porque o detector precisa executar nas
  páginas visitadas; não devem ser ampliadas;
- mensagens devem aceitar somente esquemas HTTP(S), remetente de aba esperado e
  objetos normalizados;
- o estado do aviso deve usar token opaco de sessão em vez de serializar URL e
  razões na query;
- a política CSP padrão de extensões MV3 é adequada; nenhuma exceção para script
  remoto ou `unsafe-eval` deve ser adicionada;
- snapshots devem continuar sem HTML bruto, valores digitados ou conteúdo DOM
  irrestrito.

## Dívida técnica e inconsistências

- `manifest.json` está em 0.4.0 e `package.json` em 0.3.0;
- README ainda descreve Dataset C como futuro e PAGE_ANALYSIS como camada
  paralela;
- os nomes globais de módulos históricos impedem carregá-los juntos no mesmo
  contexto; a V4 deve usar nomes próprios;
- scripts de avaliação foram criados em momentos distintos e precisam de uma
  biblioteca comum de métricas/hashes para a V4;
- resultados históricos devem permanecer somente leitura e receber referências,
  nunca sobrescrita.

## Direção aprovada para implementação

1. criar módulos internos `analysis-v4.js`, `page-analysis-v4.js` e
   `combined-analysis-v4.js`, preservando todos os motores históricos;
2. usar grupos de evidência e relações contextuais; sinal fraco isolado não
   decide e sinais correlatos não contam como diversidade independente;
3. executar duas capturas finitas do DOM: em `DOMContentLoaded` e 1.200 ms depois;
4. fundir as capturas por contexto, sem MutationObserver permanente;
5. integrar reputação no resultado explicável, mantendo indisponível diferente
   de não listado;
6. reservar `blocked` para reputação listada, ameaça local confirmada ou uma
   combinação excepcionalmente forte e coerente entre identidade, coleta e
   exfiltração;
7. transportar o estado do aviso por token opaco em `storage.session`;
8. adicionar testes sintéticos antes de aceitar cada regra geral;
9. usar A/B/C e o corpus conhecido apenas para regressão e registrar perdas;
10. congelar a V4 antes de coletar e selar o Dataset D.

## Critérios de rejeição

Serão rejeitadas regras baseadas em domínio específico observado nos datasets,
allowlists de falsos positivos, blacklists derivadas das avaliações, redução de
threshold sem justificativa causal ou qualquer ganho que dependa de abrir URLs
de phishing. A avaliação independente no Dataset D será executada uma única vez
depois do freeze.
