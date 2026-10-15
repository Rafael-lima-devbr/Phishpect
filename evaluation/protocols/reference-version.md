# Versão de referência da validação final

## Identificação

- Projeto: Phishpect MVP
- Versão da extensão: `0.4.0` (`manifest.json`)
- Versão registrada no pacote: `0.3.0` (`package.json`, divergência preexistente mantida)
- Branch de referência: `main`
- Commit do detector: `7e59a5b26e0eaf9f809fa63340ca97e47d2de7ab`
- Data do registro: 2026-10-15
- Fuso horário: `America/Bahia`

O commit acima identifica o comportamento do detector avaliado nesta rodada. O repositório pode continuar recebendo protocolos, scripts, datasets, resultados e documentação experimental, mas esses commits não podem mudar o comportamento congelado.

## Hashes SHA-256

| Arquivo | SHA-256 |
|---|---|
| `analysis.js` | `19de0018a92025f7259f2db7c197450697e62db86c8c95a52d7c57d34b82990f` |
| `page-analysis.js` | `5ec5328af6446c803916aabcd0b02a9356e9724b0d84920534e0f36e1452fa71` |
| `combined-analysis.js` | `29065e7b22bb1650d184267ec77857bcd5ee48618058a1451a5f2c07b2059d19` |
| `reputation.js` | `9831a12fb2cb3baf1716748ff6c18a96d2c0b30de2be2f03872fa8ba5aac090f` |
| `content.js` | `eceeb2dd386338b81c2f648a5808948567442542f8e699fbdcd4337eabfe78ec` |
| `background.js` | `940d88243a5d8bcfda19d831b70d85805eb4dedcb93824445847a3737d849d07` |
| `analysis-v2.js` | `623d9bdd29077dee0bf67dbc38ddbe8a1f111105a4ccb45cd5988cf7d775a7c6` |
| `analysis-v3.js` | `0609fdcf3211d721627b9c6da734d33e41d513326f78fbf2105ae1f3d4d18d99` |
| `reputation/threat-db.json` | `07dd71625e16eaa12d7fe77a085abc0549c51af7e2467f58300b4f2f9c9bfe36` |
| `vendor/tldts.umd.min.js` | `a1eba2eb7c344202536f53749456ea1178f2217f1e5e4da110cc36a4cd6162d1` |

Os mesmos valores estão em `scripts/validation/frozen-reference.js` e são verificados antes da avaliação oficial.

## Regras metodológicas

Durante esta rodada não podem ser modificados pesos, thresholds, listas de marcas, combinações, regras de classificação, política de `blocked`, arquitetura ou os motores V2, V3 e V3.1. A análise de página e a combinação também permanecem fixas.

O Dataset C deve ser construído e selado sem chamar o detector. A primeira execução sobre seu hash final será a avaliação oficial. Nenhum resultado poderá ser usado para recalibrar esta versão. Depois da inspeção dos erros, C deixa de ser independente para qualquer versão futura construída com esse conhecimento.
