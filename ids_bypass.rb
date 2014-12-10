#!/usr/bin/env ruby
# -*- coding: binary -*-
require 'packetfu'
require 'socket'
require 'netaddr'

iface = ARGV[0] || "eth0"
ahosts = ARGV[1] || "127.0.0.1"
aports = ARGV[2] || "8080"

def connect(host, port, timeout = 5)

  # Convert the passed host into structures the non-blocking calls
  # can deal with
  addr = Socket.getaddrinfo(host, nil)
  sockaddr = Socket.pack_sockaddr_in(port, addr[0][3])

  Socket.new(Socket.const_get(addr[0][0]), Socket::SOCK_STREAM, 0).tap do |socket|
    socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

    begin
      # Initiate the socket connection in the background. If it doesn't fail
      # immediatelyit will raise an IO::WaitWritable (Errno::EINPROGRESS)
      # indicating the connection is in progress.
      socket.connect_nonblock(sockaddr)

    rescue IO::WaitWritable
      # IO.select will block until the socket is writable or the timeout
      # is exceeded - whichever comes first.
      if IO.select(nil, [socket], nil, timeout)
        begin
          # Verify there is now a good connection
          socket.connect(sockaddr)
        rescue Errno::EISCONN
          # Good news everybody, the socket is connected!
        rescue
          # An unexpected exception was raised - the connection is no good.
          socket.close
          raise
        end
      else
        # IO.select returns nil when the socket is not ready before timeout
        # seconds have elapsed
        socket.close
        raise "Connection timeout"
      end
    end
  end
end

def analyse(iface, hosts, ports)
  cap = PacketFu::Capture.new(:iface => iface, :start => true, :filter => "tcp")
  cap.stream.each do |pkt|
    packet = PacketFu::Packet.parse pkt
    if hosts.index(packet.ip_saddr) && ports.index(packet.tcp_src) && packet.tcp_flags.fin == 1
      print "#{packet.ip_saddr}:#{packet.tcp_src} is open\n"
    end
  end
end

hosts = NetAddr::CIDR.create(ahosts)
ports = []

sports = aports.split(',')

for tport in sports
    if tport.index('-')
      aports = (tport.split('-')[0].to_i..tport.split('-')[1].to_i+1).to_a
      ports += aports
    else
      ports << tport.to_i
    end
end
ports = ports.uniq.sort

sn = Thread.new {analyse(iface, hosts.enumerate, ports)}


max_pool = 30
threads = []
sockets = []
host_t = []
port_t = []

sleep(1)

for host in hosts.enumerate
  for port in ports
      threads.delete_if { |thr| thr.stop? }
      if threads.length<max_pool
        threads << Thread.new(host,port) {
          |h,p|
          begin
            s = connect(h, p, 0.1)
            s.close()
          rescue Exception
          end
        }
      else
        begin
          s = connect(host, port, 0.1)
          s.close()
        rescue Exception
        end
      end
  end
end

sleep(5)