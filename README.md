# did-btcr2-rust

## One-time Setup

You must initialize the git submodules after cloning the repo:

```bash
git submodule init
git submodule update
```


## Some goals for this implementation:

- Don't stringify and reparse a bunch of times: we want strong types.
- Make things nice for rustaceans.
- Worry about unnecessary allocations.

