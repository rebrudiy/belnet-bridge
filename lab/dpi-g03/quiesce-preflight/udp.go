// Command udp emits bounded development traffic; it is not a BelNet client.
package main

import (
 "bytes"
 "encoding/binary"
 "encoding/json"
 "fmt"
 "net"
 "os"
 "time"
)

func main() {
 if len(os.Args) != 2 { panic("echo|traffic") }
 if os.Args[1] == "echo" {
  c, err := net.ListenPacket("udp4", "127.0.0.1:12092"); if err != nil { panic(err) }; defer c.Close()
  b := make([]byte, 65535)
  for { n, p, err := c.ReadFrom(b); if err != nil { return }; if _, err = c.WriteTo(b[:n], p); err != nil { panic(err) } }
 }
 if os.Args[1] != "traffic" { panic("unknown role") }
 c, err := net.Dial("udp4", "127.0.0.1:2093"); if err != nil { panic(err) }; defer c.Close()
 start := time.Now(); sent, exact, failed := 0, 0, 0; first, last := int64(0), int64(0)
 for time.Since(start) < 8*time.Second {
  b := make([]byte, 1200); binary.BigEndian.PutUint64(b, uint64(sent)); for i:=8;i<len(b);i++ { b[i]=byte((i+sent)%251) }
  _ = c.SetDeadline(time.Now().Add(150*time.Millisecond)); _, err = c.Write(b); sent++
  reply := make([]byte, 65535); n:=0; if err == nil { n, err = c.Read(reply) }
  if err == nil && bytes.Equal(b, reply[:n]) { exact++; last=time.Now().UnixMicro(); if first==0 { first=last } } else { failed++ }
  time.Sleep(25*time.Millisecond)
 }
 result := map[string]any{"native_belnet":false,"started_unix_micros":start.UnixMicro(),"finished_unix_micros":time.Now().UnixMicro(),"sent":sent,"exact":exact,"failed":failed,"first_exact_unix_micros":first,"last_exact_unix_micros":last}
 if err:=json.NewEncoder(os.Stdout).Encode(result);err!=nil { fmt.Fprintln(os.Stderr,err);os.Exit(1) }
}
