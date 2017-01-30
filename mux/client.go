package main

import (
  "os"
  "net"
  "log"
  "time"
  "github.com/xtaci/smux"
)

func main() {
  log.Println("Listening on " + os.Args[2]);
  log.Println("Temp port is " + os.Args[1]);

  time.Sleep(2 * time.Millisecond)

  listenConn, err := net.Listen("tcp", ":" + os.Args[2])
  if err != nil {
    panic(err)
  }

  smuxConn, err := net.Dial("tcp", "127.0.0.1:" + os.Args[1])
  if err != nil {
    panic(err)
  }

  log.Println("New smux connection.")

  smuxSession, err := smux.Client(smuxConn, nil)
  if err != nil {
    panic(err)
  }

  for {
    clientConn, err := listenConn.Accept()

    log.Println("New client connection.")

    if smuxSession.IsClosed() {
      clientConn.Close()
      smuxConn.Close()
      panic("Restarting client")
    }

    stream, err := smuxSession.OpenStream()

    if err != nil {
      clientConn.Close()
      smuxConn.Close()
      panic("Restarting client")
    }

    go handleClientRead(clientConn, stream)
    go handleClientWrite(clientConn, stream)

  }

}

func handleClientRead(conn net.Conn, stream *smux.Stream) {
  for {
    buf := make([]byte, 1024)
    _, err := conn.Read(buf)

    if err != nil {
      // log.Println(err)
      conn.Close()
      stream.Close()
      return
    }

    stream.Write(buf)
  }
}

func handleClientWrite(conn net.Conn, stream *smux.Stream) {
  for {
    buf := make([]byte, 1024)
    _, err := stream.Read(buf)

    if err != nil {
      // log.Println(err)
      conn.Close()
      stream.Close()
      return
    }

    conn.Write(buf)
  }
}
