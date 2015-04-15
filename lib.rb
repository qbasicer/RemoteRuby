require 'socket'
require 'json'
require 'open3'
require 'pty'

module Harness

	class IOPump
		def initialize()
			@io_list = []
			@running = false
			@verbose = false
		end
		def verbose=(val)
			@verbose = val
		end
		def add(io)
			@io_list.push(io) unless @io_list.include?(io)
			puts "Added #{io.class}, now at #{@io_list.length}" if @verbose
		end
		def remove(io)
			@io_list.delete(io) if @io_list.include?(io)
			puts "Removed #{io.class}, now at #{@io_list.length}" if @verbose
		end

		def run
			@running = true
			while (@running) do
				write_list = @io_list.select{|sock| sock.writeable?}
				read_list = @io_list.select{|sock| sock.readable?}
				rl, wl = IO.select(read_list, write_list, [], 5)

				if (rl)
					rl.each{|sock|
						puts "[#{Time.now}] READ event on #{sock.class}" if @verbose
						sock.do_read(self)
					}
				end

				if (wl)
					wl.each{|sock|
						puts "[#{Time.now}] WRITE event on #{sock.class}" if @verbose
						sock.do_write(self)
					}
				end
			end
		end

		def stop
			@running = false
		end
	end

	class Server
		def initialize(port)
			@server = TCPServer.new port
			@on_connect = []
			@verbose = false
		end

		def writeable?
			false
		end

		def readable?
			true
		end

		def verbose=(val)
			@verbose = val
		end

		def do_read(pump)
			sock = @server.accept
			puts "[#{Time.now}] New connection from #{sock.peeraddr}" if @verbose
			c = ServerClient.new(sock)
			c.verbose = @verbose
			pump.add(c)

			@on_connect.each{|evt|
				evt.call(c)
			}
		end

		def on_connect(&blk)
			@on_connect.push blk
		end

		def to_io
			@server
		end
	end

	class CommandChannelServer
		def initialize(channel, client)
			@client = client
		end

		def read(channel, indata)
			data = JSON.parse(indata)
			if (data["cmd"] == "execute") then

				args = data["args"]

				output, input, pid = PTY.spawn(*args)

				odata = {}
				odata["cmd"] = "newchannel"
				odata["name"] = "stdout"
				odata["type"] = "out"
				odata["index"] = 1
				write(0, JSON.pretty_generate(odata))

				stdout_channel = IOChannel.new(1, @client)
				pipe = PipeToChannel.new(output, stdout_channel)
				@client.pump.add(pipe)

				odata["cmd"] = "newchannel"
				odata["name"] = "stdin"
				odata["type"] = "in"
				odata["index"] = 2
				write(0, JSON.pretty_generate(odata))

				pipe = ChannelToPipe.new(input)
				@client.connect_channel(2, pipe)
				@client.pump.add(pipe)
			else
				puts "Unrecognized data #{indata}"
			end
		end

		def send_closed_channel(channelno)
			cmd = {}
			cmd["cmd"] = "closechannel"
			cmd["index"] = channelno

			write(0, JSON.pretty_generate(cmd))
		end

		def write(channel, data)
			@client.write(channel, data)
		end
	end

	class CommandChannelClient
		def initialize(channel, client)
			@client = client
		end

		def read(channel, indata)
			data = JSON.parse(indata)
			if (data["cmd"] == "newchannel") then
				pipe = $stdout if data["name"] == "stdout"
				pipe = $stderr if data["name"] == "stderr"
				pipe = $stdin if data["name"] == "stdin"

				if (data["type"] == "out") then
					#puts "***** CONNECTING NEW PIPE FOR #{data["name"]}"
					
					pipe = ChannelToPipe.new(pipe)

					pipe.verbose = true

					@client.connect_channel(data["index"], pipe)
					@client.pump.add(pipe)
				elsif (data["type"] == "in") then
					#puts "***** CONNECTING NEW PIPE FOR #{data["name"]}"
					channel = IOChannel.new(data["index"], @client)
					pipe = PipeToChannel.new(pipe, channel)
					@client.pump.add(pipe)
				end
			elsif (data["cmd"] == "closechannel") then
				@client.drop_channel(data["index"])
			else
				puts "Unrecognized data #{indata}"
			end
		end

		def send_closed_channel(channelno)
			cmd = {}
			cmd["cmd"] = "closechannel"
			cmd["index"] = channelno

			write(0, JSON.pretty_generate(cmd))
		end

		def write(channel, data)
			@client.write(channel, data)
		end

	end

	class ChannelToPipe
		def initialize(io, insert_cr: false, output_file: nil)
			@io = io
			@write_buffer = ""
			@insert_cr = insert_cr
			@f = nil
			if (output_file) then
				@f = File.open(output_file, "w")
				@f.sync = true
			end
			@verbose = false
		end

		def verbose=(val)
			@verbose = val
		end

		def write(data)
			#puts "Buffering #{data.length} to #{@io.class}"
			@write_buffer = "#{@write_buffer}#{data}"
		end

		def do_write(pump)
			result = @io.write_nonblock(@write_buffer)
			#puts "Write #{result} to #{@io.class}"
			if (result == @write_buffer.length)
				@write_buffer = ""
			else
				@write_buffer = @write_buffer[result..-1]
				raise "Bad realign" if @write_buffer.nil?
			end
			@pump = pump
		end

		def do_read(pump)
			result = @io.read_nonblock(1024)

			raise "Read #{result}"
		end


		def readable?
			false
		end

		def writeable?
			@write_buffer.length > 0
		end

		def to_io
			@io
		end

		def read(channel, data)
			write(data)
		end
	end

	class IOChannel
		def initialize(channel, client)
			@client = client
			@channel = channel
		end

		def close(io)
			@client.pump.remove(io)
			@client.close_channel(@channel)
		end

		def write(data)
			@client.write(@channel, data)
		end
	end

	class PipeToChannel
		def initialize(io, channel)
			@io = io
			@channel = channel
		end

		def readable?
			true
		end

		def do_read(pump)
			begin
				result = to_io.read_nonblock(1024)
				@channel.write(result)

				#puts "CHAN #{@channel} READ #{result}"
			rescue Exception=>e
				puts "Channel closed #{@channel} closed!"
				@channel.close(self)
			end
		end

		def writeable?
			false
		end

		def to_io
			@io
		end
	end

	class CommonClient
		def readable?
			true
		end

		def write(channel, data)
			newdata = [channel].pack("S")

			newdata = "#{newdata}#{data}"

			length = [newdata.length].pack("L")

			write_impl("#{length}#{newdata}")
		end

		def do_read(pump)
			@buffer ||= ""
			result = to_io.read_nonblock(1024)
			raise "No data" if result.nil? || result.empty?

			@buffer = "#{@buffer}#{result}"

			while (@buffer.length > 4) do
				length = @buffer[0..4]
				length = length.unpack("L").first

				if (@buffer.length >= length + 4) then
					channel = @buffer[4, 2].unpack("S").first
					data = @buffer[6, length-2]
					@buffer = @buffer[length + 4..-1]
					read_channel(channel, data)
				else
					raise "Invalid read event"
				end
			end
		end

		def read_channel(channel, data)
			@channels ||= {}
			raise "No connected channel #{channel}" unless @channels.include?(channel)
			@channels[channel].read(channel, data)
		end

		def close_channel(channelno)
			@channels ||= {}
			if (channelno != 0) then
				@channels[0].send_closed_channel(channelno)
			end
			drop_channel(channelno)
		end

		def drop_channel(channelno)
			@channels ||= {}
			c = @channels[channelno]

			pump.remove(c) unless c.nil?

			@channels.delete(channelno)
		end

		def connect_channel(channelno, channel)
			@channels ||= {}
			@channels[channelno] = channel
		end
	end

	class ServerClient < CommonClient
		def initialize(sock)
			@sock = sock
			@write_buffer = ""
			@channels = {}
			@pump = nil
			@verbose = false
		end

		def verbose=(val)
			@verbose = val
		end

		def do_write(pump)
			puts "[#{Time.now}] Writing to IO - #{@write_buffer}" if @verbose
			result = @sock.write_nonblock(@write_buffer)
			if (result == @write_buffer.length)
				@write_buffer = ""
			else
				@write_buffer = @write_buffer[result..-1]
			end
			@pump = pump
		end

		def pump
			raise "No pump" if @pump.nil?
			@pump
		end

		def pump=(pump)
			@pump = pump
		end

		def write_impl(data)
			@write_buffer = "#{@write_buffer}#{data}"
		end

		def writeable?
			@write_buffer.length > 0
		end

		def to_io
			@sock
		end
	end

	class Client < CommonClient
		def initialize(host, port)
			@client = TCPSocket.new(host, port)
			@write_buffer = ""
			@pump = nil
			@verbose = nil
		end

		def verbose=(val)
			@verbose = val
		end

		def do_write(pump)
			puts "[#{Time.now}] Writing to IO - #{@write_buffer}" if @verbose
			result = @client.write_nonblock(@write_buffer)
			if (result == @write_buffer.length)
				@write_buffer = ""
			else
				@write_buffer = @write_buffer[result]
			end
			@pump = pump
		end

		def write_impl(data)
			@write_buffer = "#{@write_buffer}#{data}"
		end

		def writeable?
			@write_buffer.length > 0
		end

		def execute(array)
			cmd = {}
			cmd["cmd"] = "execute"
			cmd["args"] = array

			puts "WARNING - You are about to execute a command on a remote host, transferring control"

			write(0, JSON.pretty_generate(cmd))
		end

		def to_io
			@client
		end

		def pump=(pump)
			@pump = pump
		end

		def pump
			raise "No pump" if @pump.nil?
			@pump
		end
	end
end