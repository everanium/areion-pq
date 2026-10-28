# Builds the AES-NI / PCLMULQDQ integral and QuickSilver GF(2^128) check binary.
BUILD ?= ../build
CFLAGS ?= -O3 -march=native

$(BUILD)/pq_integral: pq_integral.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -pthread -o $@.tmp pq_integral.c && mv $@.tmp $@

.PHONY: clean
clean:
	rm -f $(BUILD)/pq_integral
