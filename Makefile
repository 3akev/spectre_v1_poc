all: clean spectre victim

victim: victim.c
	gcc $^ -g -o $@

spectre: spectre.c
	gcc $^ -g -o $@

poc: poc.c
	gcc $^ -o $@

clean:
	ipcrm --all
	rm -f poc spectre victim

.PHONY: clean
