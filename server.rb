require_relative 'lib.rb'

raise "No such file 'key.allow'.  Each line is the SHA1 hash of the key to allow (see stdout on client start)" unless File.exist?("key.allow")

if (!File.exist?("dh.key")) then
	puts "Generating new Diffie-Hellman key, this may take a few moments"
	dh = OpenSSL::PKey::DH.new(2048)
	File.open("dh.key", "w"){|f| f.write(dh.to_der)}
	File.chmod(0600, "dh.key")
	puts "Completed generating key"
end


server = Harness::Server.new(2000)

pump = Harness::IOPump.new

server.on_connect{|socket|
	socket.pump = pump
	socket.connect_channel(0, Harness::KeyServer.new(0, socket))
	#socket.connect_channel(0, Harness::CommandChannelServer.new(0, socket))
}

pump.add(server)

pump.run