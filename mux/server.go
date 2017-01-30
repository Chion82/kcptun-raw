package main

import (
  "os"
  "net"
  "log"
  "github.com/xtaci/smux"
)

func main() {
  log.Println("Target: " + os.Args[1] + ":" + os.Args[2])
  log.Println("Temp port is " + os.Args[3])

  listenConn, err := net.Listen("tcp", "127.0.0.1:" + os.Args[3])
  if err != nil {
    panic(err)
  }

  for {
    smuxConn, err := listenConn.Accept()

    if err != nil {
      continue
    }

    go handleSmuxConn(smuxConn)
  }

}

func handleSmuxConn(smuxConn net.Conn) {
  log.Println("New smux connection.")

  smuxSession, err := smux.Server(smuxConn, nil)
  if err != nil {
    return
  }

  for {
    stream, err := smuxSession.AcceptStream()
    if err != nil {
      smuxConn.Close()
      break
    }

    log.Println("New client connection.")
    go handleIncomingStream(stream)
  }
}

func handleIncomingStream(stream *smux.Stream) {
  conn, err := net.Dial("tcp", os.Args[1] + ":" + os.Args[2])
  if err != nil {
    log.Println("Target " + os.Args[1] + ":" + os.Args[2] + " could not reach.")
    stream.Close()
    return
  }
  go handleStreamRead(conn, stream)
  go handleStreamWrite(conn, stream)
}

func handleStreamRead(conn net.Conn, stream *smux.Stream) {
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

func handleStreamWrite(conn net.Conn, stream *smux.Stream) {
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
