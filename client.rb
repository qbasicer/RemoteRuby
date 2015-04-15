require_relative 'lib.rb'
require 'termios'

old_attrs = Termios.tcgetattr(STDOUT)
new_attrs = old_attrs.dup
new_attrs.lflag &= ~Termios::ECHO
new_attrs.lflag &= ~Termios::ICANON

Termios::tcsetattr(STDOUT, Termios::TCSANOW, new_attrs)

trap("SIGINT") {
	Termios::tcsetattr(STDOUT, Termios::TCSANOW, old_attrs)
	exit!
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
	}

	


	pump.run
ensure
	puts "Connection has been terminated"
	Termios::tcsetattr(STDOUT, Termios::TCSANOW, old_attrs)
end