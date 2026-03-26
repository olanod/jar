BOOK_BIN := .lake/build/bin/jarbook

TEST_BINS := cryptotest safrolejsontest historyjsontest statisticsjsontest \
             authorizationsjsontest disputesjsontest preimagesjsontest \
             assurancesjsontest reportsjsontest accumulatejsontest propertytest \
             trietest shuffletest codectest blocktest erasuretest genesistest

.PHONY: book clean test

book: $(BOOK_BIN)
	$(BOOK_BIN)

$(BOOK_BIN):
	lake build jarbook

test:
	lake build $(TEST_BINS)
	@fail=0; \
	for bin in $(TEST_BINS); do \
	  echo "── $$bin ──"; \
	  .lake/build/bin/$$bin || fail=1; \
	done; \
	exit $$fail

clean:
	rm -rf _out
