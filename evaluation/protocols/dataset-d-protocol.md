# Protocolo prévio — Dataset D

Status: **defined-before-acquisition**  
Versão: Phishpect V4 congelada em `evaluation/protocols/v4-reference.md`  
Seed: `phishpect-dataset-d-2026-10-22-v1`  
Fuso: `America/Bahia`

## Objetivo

Realizar uma única validação independente da V4 depois do congelamento. A seleção não
consulta o detector, scores, categorias ou classificações.

## Composição planejada

- 100 URLs legítimas;
- 100 URLs phishing;
- classes balanceadas;
- uma URL por domínio registrável em cada classe;
- nenhum domínio compartilhado entre classes.

Se uma fonte não fornecer candidatos elegíveis suficientes, admite-se entre 150 e
200 amostras totais, com classes aproximadamente balanceadas, sem relaxar filtros.

## Fontes

### Phishing

OpenPhish Community Feed, adquirido depois do congelamento e preservado como texto
bruto. O feed nunca será aberto em navegador, resolvido ou visitado. PhishTank não é
obrigatório: o endpoint público já apresentou HTTP 429 e o cadastro de novas contas
estava indisponível na preparação anterior. Nenhuma fonte substituta será introduzida
silenciosamente.

### Legítimas

Seleção determinística de registros documentais já preservados de Tranco, Wikidata e
GitHub Pages, acrescida, quando disponível, de uma lista Tranco obtida após o
congelamento. Registros usados no Dataset C são excluídos. Não há visita às páginas e
não se usa aparência visual nem saída do Phishpect.

Estratos-alvo, usados como diversidade e não como cotas rígidas:

- autenticação e páginas internas;
- e-commerce e finanças;
- SaaS e shared hosting;
- URLs longas ou com query;
- IDN/Punycode;
- estrutura incomum;
- páginas gerais.

## Normalização e filtros — ordem fixa

1. URL HTTP(S) sintaticamente válida;
2. normalização de protocolo, hostname, porta padrão, fragmento e trailing slash;
3. duplicata normalizada;
4. equivalência hostname + porta + path;
5. overlap com Dataset A;
6. overlap com Dataset B;
7. overlap com Dataset C;
8. overlap histórico por URL normalizada ou hostname + path;
9. correspondência na reputação congelada;
10. repetição de domínio registrável na classe;
11. domínio presente na classe oposta.

Cada remoção recebe um contador. Os critérios não serão reduzidos para completar a
amostra.

## Seleção determinística

Dentro de cada classe e estrato, a ordem é SHA-256 de:

`seed + NUL + URL normalizada`

O Dataset D é selado com manifesto, hashes de fontes, contadores, composição, seed e
SHA-256 do CSV. O estado anterior à execução é `sealed-not-evaluated`.

## Avaliação oficial única

O avaliador deve:

- recusar divergência de qualquer hash congelado;
- recusar dataset não selado, composição incorreta ou resultado preexistente;
- exigir `--confirm-official`;
- produzir TP, TN, FP, FN, recall, precision, F1, accuracy e FAR;
- produzir IC95% de Wilson para recall e FAR;
- preservar por URL score, categorias, sinais, motivos, reputação e decisão final;
- registrar ambiente, comando, commit, hash do dataset e hashes dos artefatos.

A avaliação oficial de URL mede a decisão inicial integrada da V4 (URL + reputação).
O componente pós-carregamento exige snapshots HTML e é avaliado separadamente no
corpus conhecido. Um novo conjunto independente de páginas somente será usado se
puder ser montado de forma inerte, auditável e sem visitar phishing; sua ausência é
registrada como limitação e não é ocultada por snapshots vazios artificiais.

## Segurança e não interferência

- URLs phishing são apenas dados de texto.
- Nenhuma URL phishing é aberta, consultada ou executada.
- Nenhuma página remota é carregada durante seleção ou avaliação.
- A V4 não pode ser alterada depois de observar o resultado.
- Dataset D passa a ser dado de desenvolvimento para qualquer versão futura que use
  seus erros para refinamento.
