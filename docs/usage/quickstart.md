# Quick Start

```bash
dont_be_lazy --help
```

## Scan the current repository

```bash
dont_be_lazy scan .
```

## Show a summary by risk

```bash
dont_be_lazy summary . --by risk
```

## Find stale suppressions

```bash
dont_be_lazy stale . --older-than 180d --with-git-history
```

## Explain one finding

```bash
dont_be_lazy explain path/to/file.py:42
```

## Track accepted suppressions with a baseline

```bash
dont_be_lazy baseline create . --output .dont-be-lazy-baseline.json
dont_be_lazy baseline check . --baseline .dont-be-lazy-baseline.json
```

## Test built-in policy rules

```bash
dont_be_lazy rules list
dont_be_lazy rules test .
```
