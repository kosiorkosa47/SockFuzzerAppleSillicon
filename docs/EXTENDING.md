# Extending SockFuzzer

## Adding a New Syscall

### Step 1: Add the wrapper function

In `fuzz/api/syscall_wrappers.h`, declare:
```c
int my_syscall_wrapper(int arg1, int arg2, int* retval);
```

In `fuzz/api/syscall_wrappers.c`, implement:
```c
__attribute__((visibility("default"))) int my_syscall_wrapper(
    int arg1, int arg2, int* retval) {
  struct my_syscall_args uap = {
      .arg1 = arg1,
      .arg2 = arg2,
  };
  return my_syscall(kernproc, &uap, retval);
}
```

### Step 2: Export the symbol

Add `_my_syscall_wrapper` to `cmake/xnu_exported_symbols.txt`.

### Step 3: Define the protobuf message

In `fuzz/net_fuzzer.proto`, add:
```protobuf
message MySyscall {
  optional int32 arg1 = 1;
  optional int32 arg2 = 2;
}
```

Add to the `Command` oneof:
```protobuf
    MySyscall my_syscall = <next_field_number>;
```

### Step 4: Add the handler

In `fuzz/net_fuzzer.cc`, in the main switch:
```cpp
case Command::kMySyscall:
  my_syscall_wrapper(command.my_syscall().arg1(),
                     command.my_syscall().arg2(), &retval);
  break;
```

### Step 5: Build and test

```bash
cd build && cmake .. && make -j
./net_fuzzer corpus/ -max_total_time=60
```

Check coverage to verify the new syscall is reached.

## Adding a New Packet Type

### Step 1: Define the header struct

In `fuzz/types.h`:
```c
struct my_protocol_hdr {
  uint8_t field1;
  uint16_t field2;
} __attribute__((__packed__));
```

### Step 2: Define protobuf messages

In `fuzz/net_fuzzer.proto`:
```protobuf
message MyProtocolHdr {
  required uint32 field1 = 1;
  required uint32 field2 = 2;
}

message MyProtocolPacket {
  required IpHdr ip_hdr = 1;
  required MyProtocolHdr my_hdr = 2;
  optional bytes data = 3;
}
```

Add to the `Packet` oneof:
```protobuf
    MyProtocolPacket my_protocol_packet = <next_field_number>;
```

### Step 3: Implement builder and handler

In `fuzz/net_fuzzer.cc`:
```cpp
std::string get_my_protocol_hdr(const MyProtocolHdr &hdr) {
  struct my_protocol_hdr h = {
      .field1 = (uint8_t)hdr.field1(),
      .field2 = (uint16_t)hdr.field2(),
  };
  return std::string((char *)&h, (char *)&h + sizeof(h));
}

void DoMyProtocolInput(const MyProtocolPacket &pkt) {
  size_t expected = sizeof(struct ip) + sizeof(struct my_protocol_hdr)
                    + pkt.data().size();
  std::string s = get_ip_hdr(pkt.ip_hdr(), expected);
  s += get_my_protocol_hdr(pkt.my_hdr());
  s += pkt.data();

  void *m = get_mbuf_data(s.data(), s.size(), PKTF_LOOP);
  if (!m) return;
  ip_input_wrapper(m);
}
```

Add to `DoIpInput()` switch.

## Adding a New Ioctl

### Step 1: Export the constant

In `fuzz/api/ioctl.c`:
```c
__attribute__((visibility("default"))) const unsigned long my_ioctl_val =
    MY_IOCTL_CMD;
```

Add `_my_ioctl_val` to `cmake/xnu_exported_symbols.txt`.

### Step 2: Define structured message

In `fuzz/net_fuzzer.proto`, add to `IoctlReal` oneof:
```protobuf
    MyIoctlReq my_ioctl = <next_field_number>;
```

### Step 3: Add handler

In `HandleIoctlReal()`:
```cpp
case IoctlReal::kMyIoctl: {
  struct my_ioctl_struct req = {};
  // populate from proto
  ioctl_wrapper(command.ioctl_real().fd(), my_ioctl_val,
                (caddr_t)&req, nullptr);
  break;
}
```

## Implementing a Stub

When the fuzzer crashes with `STUB HIT: some_function`, that function
needs an implementation.

1. Find the function signature in XNU source
2. Determine if it needs a real implementation or a safe no-op
3. Move it from `stubs.c` (STUB_ABORT) to `fake_impls.c` with proper logic
4. Common patterns:
   - Lock operations → no-op (single-threaded)
   - Allocation → malloc/calloc
   - Time queries → use `g_fake_time_counter`
   - Permission checks → `get_fuzzed_bool()` for random success/fail
   - Thread operations → immediate return
