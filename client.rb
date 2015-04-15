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

	client = Harness::Client.new("localhost", 2000)

	pump = Harness::IOPump.new

	pump.add(client)

	client.pump = pump

	client.execute(["bash", "-l"])

	client.connect_channel(0, Harness::CommandChannelClient.new(0, client))


	pump.run
ensure
	puts "Connection has been terminated"
	Termios::tcsetattr(STDOUT, Termios::TCSANOW, old_attrs)
end