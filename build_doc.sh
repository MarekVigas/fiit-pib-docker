#!/usr/bin/env bash

pandoc doc.md -o doc.pdf --from markdown --template eisvogel --toc --number-sections --highlight-style zenburn -V fontsize=12pt