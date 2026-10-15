# Protocolo preliminar — benchmark no Microsoft Edge

Status: preparado, não executado.

O benchmark será um harness separado e não modificará o detector congelado.

## Ambiente registrado

- versão completa do Microsoft Edge;
- versão do Windows;
- CPU e RAM;
- commit do detector;
- versão da extensão;
- modo de carregamento;
- outras extensões desabilitadas;
- condição de energia do computador.

## Páginas locais

- pequena: 1 formulário e até 10 campos;
- média: aproximadamente 10 formulários e 200 campos;
- grande: 30 formulários e até 2.400 campos, atingindo os limites atuais.

Somente páginas locais e URLs reservadas serão usadas.

## Medições

- `analyzeUrl`;
- `collectPageSnapshot`;
- `analyzePage`;
- `combineAnalyses`;
- total pós-carregamento.

Para cada condição: 30 aquecimentos e 100 observações medidas, com ordem pseudoaleatória registrada. Serão preservadas todas as durações e calculados média, mediana, p95, mínimo e máximo.

O harness poderá usar `performance.mark`, `performance.measure` ou `performance.now`. O resultado mede custo computacional controlado; não autoriza afirmar ausência de lentidão perceptível sem dados adicionais de navegação.
