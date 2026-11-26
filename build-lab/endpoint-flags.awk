# Change exactly the successful build's endpoint object rule before compilation.
BEGIN {
    target = "build llarp/CMakeFiles/belnet-amalgum.dir/service/endpoint.cpp.o:"
    targets = 0
    changes = 0
}
/^build / {
    inside = index($0, target) == 1
    if (inside) targets++
}
inside && /^  FLAGS = / {
    if ($0 !~ /^  FLAGS = -O3 -DNDEBUG /) {
        print "Unexpected endpoint compiler flags; refusing override" > "/dev/stderr"
        invalid = 1
        exit 2
    }
    changes += sub(/-O3 -DNDEBUG/, "-O0 --param ggc-min-expand=5 --param ggc-min-heapsize=32768 -DNDEBUG")
}
{ print }
END {
    if (invalid || targets != 1 || changes != 1) {
        print "Expected exactly one endpoint flag override" > "/dev/stderr"
        exit 2
    }
}
