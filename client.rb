require 'termios'
require_relative 'lib.rb'


rows,cols = $stdout.winsize
puts "Rows: #{rows}, Cols: #{cols}"

old_attrs = Termios.tcgetattr(STDOUT)
new_attrs = old_attrs.dup
new_attrs.lflag &= ~Termios::ECHO
new_attrs.lflag &= ~Termios::ICANON

Termios::tcsetattr(STDOUT, Termios::TCSANOW, new_attrs)

client = nil
pump = nil

trap("SIGINT") {
	# Try delivering the signal to the other side
	r = client.deliver_signal("SIGINT")

	# Writes a single byte to a pipe so that IO.select will wakeup immediately and we can flush out our buffers, otherwise we gotta wait 5 seconds
	pump.wake

	# If the client didn't want it, terminate immediately
	Termios::tcsetattr(STDOUT, Termios::TCSANOW, old_attrs) if !r
	exit if !r
}

Signal.trap('SIGWINCH') {
	client.channels[3].send_term_size
	# Writes a single byte to a pipe so that IO.select will wakeup immediately and we can flush out our buffers, otherwise we gotta wait 5 seconds
	pump.wake
}
begin

	key = nil

	if (File.exist?("remote.key")) then
		key = OpenSSL::PKey::RSA.new(File.read("remote.key"))
		sha1 = Digest::SHA1.hexdigest key.public_key.to_der
		puts "Loaded key #{sha1}"
	else
		puts "Generating new key"
		key = OpenSSL::PKey::RSA.new(4096)
		File.open("remote.key", "w"){|f| f.write key.to_pem}
		sha1 = Digest::SHA1.hexdigest key.public_key.to_der
		puts "Loaded key #{sha1}"
	end
	File.chmod(0600, "remote.key")

	client = Harness::Client.new("localhost", 2000)

	pump = Harness::IOPump.new

	pump.add(client)

	client.pump = pump

	#client.connect_channel(0, Harness::CommandChannelClient.new(0, client))
	kc = Harness::KeyClient.new(0, client, key)
	client.connect_channel(0, kc)

	kc.start_key_negotiation

	kc.on_connect{
		client.execute(["bash", "-l"])
		#client.prompt
	}

	


	pump.run
ensure
	puts "Connection has been terminated"
	Termios::tcsetattr(STDOUT, Termios::TCSANOW, old_attrs)
end