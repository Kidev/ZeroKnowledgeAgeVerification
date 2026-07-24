# Build entry points for the whole repository.
#
#   make paper    build paper/paper.pdf and paper/paper.fr.pdf (latexmk + bibtex)
#   make test     run the full test suite
#   make demo     run the end-to-end demo at production parameters
#   make rust     build and selftest the native Rust PoC
#   make interop  cross-verify proofs between the Rust and Python implementations
#   make arxiv    produce dist/arxiv.tar with exactly the files arXiv needs
#   make clean    remove LaTeX build artifacts and dist/

.PHONY: all paper test demo rust rust-bench interop arxiv clean

all: paper test demo rust rust-bench interop arxiv

paper:
	cd paper && latexmk -pdf -silent -interaction=nonstopmode paper.tex
	cd paper && latexmk -pdf -silent -interaction=nonstopmode paper.fr.tex

test:
	cd code/python && python3 test_core.py

demo:
	cd code/python && python3 demo.py

rust:
	cd code/rust && cargo build --release && ./target/release/avsm-poc selftest

rust-bench: rust
	cd code/rust && ./target/release/avsm-poc bench

interop: rust
	rm -rf dist/interop && mkdir -p dist/interop
	cd code/rust && ./target/release/avsm-poc prove ../../dist/interop/rust-out
	cd code/python && python3 rust_interop.py check ../../dist/interop/rust-out
	cd code/python && python3 rust_interop.py emit ../../dist/interop/py-out 32 219
	cd code/rust && ./target/release/avsm-poc verify ../../dist/interop/py-out

arxiv: paper
	rm -rf dist/arxiv && mkdir -p dist/arxiv
	# strip LaTeX comments
	for f in paper macros; do \
	  sed -e 's/\([^\\]\)%.*/\1%/' -e '/^%[^%]/d' paper/$$f.tex > dist/arxiv/$$f.tex; \
	done
	# ask arXiv's builder for enough passes to settle references
	printf '\n\\typeout{get arXiv to do 4 passes: Label(s) may have changed. Rerun}\n' >> dist/arxiv/paper.tex
	cp paper/paper.bbl dist/arxiv/
	# verify the stripped source compiles with only tex + bbl present
	cd dist/arxiv && pdflatex -interaction=nonstopmode paper.tex > /dev/null \
	  && pdflatex -interaction=nonstopmode paper.tex > /dev/null
	cd dist/arxiv && rm -f paper.aux paper.log paper.out paper.pdf
	cd dist/arxiv && tar -cf ../arxiv.tar paper.tex macros.tex paper.bbl
	@echo "wrote dist/arxiv.tar; upload this file to arXiv"

clean:
	cd paper && latexmk -C paper.tex 2>/dev/null; latexmk -C paper.fr.tex 2>/dev/null; true
	rm -rf dist paper/*.bbl.bak code/python/__pycache__ code/rust/target
