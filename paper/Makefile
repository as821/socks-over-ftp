DOC=tcp-over-ftp

.PHONY: $(DOC).pdf all clean

all: $(DOC).pdf

$(DOC).pdf: $(DOC).tex
	latexmk -pdf -pdflatex="pdflatex -interaction=nonstopmode" -use-make $<

clean:
	latexmk -CA
