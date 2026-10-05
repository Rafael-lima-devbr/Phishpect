# Refinamento da análise de URLs — V3

## Escopo e metodologia

A V3 mantém uma análise local, explicável e baseada em regras. Não usa machine learning, DOM, conteúdo remoto nem listas arbitrárias de TLDs. As características lexicais e de identidade seguem as ideias de URL-only analysis discutidas por Butnaru, Mylonas e Pitropakis (2021) e pelo trabalho *Phishing URL Detection: A Real-Case Scenario Through Login URLs* (2022), mas os modelos de machine learning desses trabalhos não foram reproduzidos.

Os Datasets A e B foram inspecionados para selecionar e calibrar as regras. Portanto, **nenhum dos dois é validação independente da V3**. Os números abaixo são resultados de desenvolvimento e comparação retrospectiva.

## 1. Problemas encontrados na V2

- O threshold era 20 e HTTP, URL com mais de 150 caracteres ou qualquer termo sensível também valiam 20. Cada um podia gerar `suspicious` isoladamente.
- Os termos eram procurados no hostname, pathname e query concatenados. Assim, `accounts.google.com/login` recebia o mesmo peso de um termo no hostname de um domínio não oficial.
- A detecção de marcas exigia token exato e não reconhecia typos simples como `micros0ft`, `netflx` e `paypa1`.
- Não havia separação explícita entre domínio registrável e subdomínio, o que dificultava interpretar corretamente sufixos como `.co.uk` e hospedagens privadas como `github.io`.
- Hífens, dígitos, comprimento e quantidade de subdomínios tinham pesos independentes, sem registrar combinações estruturais.
- A V2 tinha bom recall nos datasets principalmente porque sinais fracos isolados alcançavam o threshold. Isso também causou o falso positivo de `accounts.google.com`.

## 2. Arquivos alterados ou adicionados

- `analysis.js`: implementação V3.
- `analysis-v2.js`: cópia preservada da V2 anterior.
- `manifest.json` e `background.js`: carregamento do parser PSL antes da V3.
- `vendor/tldts.umd.min.js`, `package.json` e `bun.lock`: dependência mínima e bundle autocontido do `tldts`.
- `tests/analysis-v2.test.js` e `tests/analysis-v3.test.js`: separação dos testes e novos casos seguros/fictícios.
- `scripts/evaluate-dataset.js`: seleção V2/V3, métricas completas, reasons, features e listas de erros.
- `README.md` e `THIRD_PARTY_NOTICES.md`: arquitetura, uso, metodologia e licença.
- `evaluation/results/refinement/`: resultados detalhados de A e B para V2 e V3.
- `evaluation/docs/v3-refinement.md`: este relatório.

## 3. Novas características

- Protocolo, hostname, domínio registrável, public suffix, subdomínios, pathname e query separados.
- Contagens de subdomínios, hífens, dígitos, parâmetros e caracteres especiais.
- Comprimentos da URL, hostname e pathname.
- Proporção de dígitos e entropia de Shannon do nome registrável.
- Termos de autenticação separados por posição: hostname, pathname e query.
- Marca exata fora de domínio oficial, marca em subdomínio alheio e typo conservador por distância de Levenshtein limitada a 1.
- Punycode contextualizado e combinado com possível imitação de marca.
- Userinfo enganoso (`marca@hostname-real`) e uso direto de IP.
- Domínio registrável derivado da Public Suffix List por `tldts`, com domínios privados habilitados.

## 4. Critérios removidos ou reduzidos

- HTTP: de 20 para 4.
- URL > 150 caracteres: de 20 para 5.
- Pathname longo: de 5 para 4, agora acima de 80 caracteres.
- Termo sensível: deixou de valer 20 independentemente da posição; pathname vale 4, query 3 e hostname 8.
- Hífens: três ou mais valem 4; dois hífens não pontuam por si só.
- Dígitos: exigem ao menos quatro e proporção mínima de 20% para valer 5.
- Muitos subdomínios: usa o subdomínio calculado pela PSL e vale 5.
- Punycode: vale 16 sozinho e precisa de contexto adicional para alcançar o threshold.

## 5. Combinações de sinais

- Marca exata fora do domínio oficial: 30 (sinal forte de identidade).
- Typo de marca: 22; não bloqueia sozinho.
- Marca/typo + termo de autenticação no hostname: +15.
- Punycode + possível imitação de marca: +15.
- Userinfo + marca antes do hostname real: 20 + 20 + bônus 10.
- IP + contexto de autenticação: 18 + sinais de posição + bônus 10.
- Múltiplos termos de autenticação no hostname: +8.
- Hospedagem compartilhada + marca/autenticação no hostname: +6.
- Hospedagem compartilhada + múltiplos termos de autenticação: +12.
- Alta entropia + hostname muito segmentado ou numérico, em hospedagem compartilhada: +21.
- A mesma combinação estrutural sob HTTP: +17.
- Clusters estruturais têm bônus, mas comprimentos de URL/path/query sozinhos continuam insuficientes.

O threshold da V3 é 30. Os pesos fracos (3–5) foram mantidos muito abaixo dele. Os valores moderados (8–22) precisam de outra evidência, enquanto uma marca exata no hostname fora de qualquer domínio oficial é tratada como evidência forte. Essa escolha foi feita após observar que A/B continham muitos acertos da V2 produzidos apenas por HTTP, mas também imitações inequívocas de marca. A calibração prioriza não repetir o falso positivo estrutural da V2.

## 6. Resultados V2 x V3

### Dataset A — desenvolvimento

| Versão | TP | FN | FP | TN | Recall | Precision | F1 | False alert rate | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| V2 | 62 | 38 | 1 | 99 | 62% | 98,41% | 76,07% | 1% | 80,5% |
| V3 | 35 | 65 | 0 | 100 | 35% | 100% | 51,85% | 0% | 67,5% |

### Dataset B — desenvolvimento, não validação independente da V3

| Versão | TP | FN | FP | TN | Recall | Precision | F1 | False alert rate | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| V2 | 59 | 41 | 1 | 99 | 59% | 98,33% | 73,75% | 1% | 79% |
| V3 | 19 | 81 | 0 | 100 | 19% | 100% | 31,93% | 0% | 59,5% |

A V3 corrige o falso alerta conhecido e detecta as imitações/typos fictícias dos testes, mas reduz bastante o recall global. Esse resultado é mantido sem maquiagem: a V2 dependia de sinais isolados que a especificação da V3 proíbe. A base local de reputação não alterou os números porque A/B foram construídos sem sobreposição com ela.

## 7. Falsos positivos restantes

Nenhum em A ou B. As listas completas, com score e reasons, estão em:

- `evaluation/results/refinement/dataset-a-v3-false-positives.csv`
- `evaluation/results/refinement/dataset-b-v3-false-positives.csv`

Isso não prova taxa real de 0%: as URLs legítimas de A/B são majoritariamente páginas de raiz de domínios populares e não representam bem URLs benignas longas, sistemas de login, CDNs ou aplicações hospedadas em plataformas compartilhadas.

## 8. Falsos negativos restantes

- Dataset A: 65.
- Dataset B: 81.

As listas completas incluem URL, score, reasons, contribuições e features:

- `evaluation/results/refinement/dataset-a-v3-false-negatives.csv`
- `evaluation/results/refinement/dataset-b-v3-false-negatives.csv`

Muitos casos restantes usam HTTPS e hostnames sem marca conhecida, autenticação, Punycode ou anomalias combinadas suficientes. Encurtadores também permanecem abaixo do threshold porque o destino real não pode ser inferido localmente sem resolver o link.

## 9. Riscos de overfitting

- A e B deixaram de ser independentes no momento em que seus erros orientaram pesos e combinações.
- A forte presença de hospedagens compartilhadas, clones de marcas e URLs Roblox pode favorecer regras específicas desse recorte temporal.
- As legítimas são simples demais e podem subestimar falsos alertas em aplicações reais.
- Ampliar vocabulário, marcas ou bônus somente para recuperar os falsos negativos listados produziria um score aparentemente melhor, mas metodologicamente frágil.

## 10. Limitações

- Análise somente lexical não identifica phishing hospedado em um domínio comum com URL neutra.
- A lista de marcas é pequena e explícita; não tenta comparar qualquer palavra da internet.
- Levenshtein é limitada a tokens relevantes e distância 1, reduzindo cobertura para conter falsos positivos.
- A V3 não decodifica Unicode por conta própria; usa o Punycode ASCII já exposto pelo URL parser e evita normalização homográfica incompleta.
- Entropia e padrões estruturais são auxiliares, não prova de fraude.
- A Public Suffix List envelhece com a versão do `tldts` e deve ser atualizada conscientemente.

## 11. Próximos passos

1. Congelar código, pesos e lista de marcas antes de coletar o Dataset C.
2. Ampliar testes benignos difíceis sem olhar o Dataset C.
3. Avaliar a V3 no Dataset C uma única vez e publicar todas as métricas e erros.
4. Se o recall continuar insuficiente, avaliar separadamente reputação atualizada e, em etapa futura, sinais de DOM/conteúdo — sem atribuir o ganho à análise lexical.

## 12. Recomendação para o Dataset C

- Coletar depois do congelamento da V3, em janela temporal posterior a A/B.
- Usar fontes de phishing e legítimas documentadas, remover duplicatas e qualquer sobreposição por URL normalizada, hostname e domínio registrável com A/B e com a base de reputação.
- Reservar C: nenhuma URL, rótulo ou métrica deve ser consultada durante nova calibração.
- Incluir legítimas difíceis: login oficial, URLs HTTP ainda válidas, URLs longas, muitos parâmetros, Punycode legítimo, subdomínios profundos, CDNs, hospedagem compartilhada, encurtadores e domínios com hífens/dígitos.
- Incluir phishing variado: marca exata, typos, Punycode, IP, userinfo, hospedagem comprometida, URLs lexicamente neutras e campanhas sem marcas da lista.
- Preferir uma distribuição que reflita uso real ou, se balanceada para análise, publicar também precision/false-alert estimates sob prevalências realistas.
- Manter proveniência, timestamp, critérios de inclusão/exclusão e hashes dos arquivos.
- Executar V2 e V3 no mesmo C congelado, sem alterar regras após observar o resultado. Qualquer ajuste posterior cria uma V4 e exige outro conjunto reservado.

## Referências

- Butnaru, A.; Mylonas, A.; Pitropakis, N. *Towards Lightweight URL-Based Phishing Detection*. Future Internet 2021, 13, 154. DOI: 10.3390/fi13060154.
- *Phishing URL Detection: A Real-Case Scenario Through Login URLs*. IEEE Access, 2022.
- `tldts`: https://github.com/remusao/tldts
