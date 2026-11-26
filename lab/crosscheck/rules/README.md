# Claude rule replay

Read-only execution of the imported Claude IPv4 classifier on our PCAP captures. classify.go is an exact source copy; types.go contains its original data structures extracted from main.go. main.go supplies PCAP input instead of NFQUEUE. No training, threshold changes or packet injection.

From the main repository root:

    GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test -race ./lab/crosscheck/rules
    GOTOOLCHAIN=local GOFLAGS=-mod=readonly go run ./lab/crosscheck/rules -out out/crosscheck/rules/replay.json lab/evolution/results/full-15-queuefix-20261119/runtime/test.pcap

Three frozen configurations: recorded iplist,size,entropy; those plus crypto; crypto alone. The known relay prefix is 10.88.0.0/24 and six public identities come from the earlier direct control. All rules only inspect IPv4 UDP. TCP, including TCP to a listed relay address, is accepted by the original implementation.

The root module supplies cached x/crypto v0.58.0 rather than the imported module's v0.59.0; a real captured IWP introduction verifies BLAKE2b behavior. See out/crosscheck/rules/source-provenance.json. Recorded byte counts include IP packets; flow counts are unique endpoint four-tuples and can merge port reuse. Offline replay reports decisions, not fresh application delivery under enforcement.
