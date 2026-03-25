Seeds are protobuf-encoded Session messages that bootstrap the fuzzer corpus.

Generate new seeds by running the fuzzer briefly and saving interesting inputs:

    ./net_fuzzer corpus/ -max_total_time=30
    cp corpus/* corpus/seeds/

Or use the fuzzer's merge mode to distill:

    ./net_fuzzer -merge=1 corpus/seeds corpus/
