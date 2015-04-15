require_relative 'lib.rb'

server = Harness::Server.new(2000)

pump = Harness::IOPump.new

server.on_connect{|socket|
	socket.pump = pump
	socket.connect_channel(0, Harness::CommandChannelServer.new(0, socket))
}

pump.add(server)

pump.run