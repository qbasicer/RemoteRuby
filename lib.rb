require 'socket'
require 'json'
require 'open3'
require 'pty'
require 'digest'
require 'openssl'
require 'base64'

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

	class KeyServer
		def initialize(channel, client)
			@client = client
			@dh = OpenSSL::PKey::DH.new(File.read("dh.key"))
			@dh.generate_key! if @dh.pub_key.nil?
			@channel = channel
			@symmkey = nil
			@iv = nil
		end
		def read(channel, indata)
			data = JSON.parse(indata)
			if (data["cmd"] == "key") then
				key = OpenSSL::PKey::RSA.new(data["key"])

				sha1 = Digest::SHA1.hexdigest key.to_der

				lines = File.read("key.allow").split("\n").map{|line| line.strip}
				allowed = false
				lines.each{|line|
					if (line == sha1) then
						allowed = true
						break
					end
				}
				raise "Client is not authorized to connect with key #{sha1}, add it to key.allow" unless allowed

				puts "Connection from key #{sha1}"

				cmd = {}
				cmd["cmd"] = "encrypted"
				cmd["key"] = sha1

				cipher = OpenSSL::Cipher::AES256.new(:CBC)
				cipher.encrypt

				params = {}
				@iv = cipher.random_iv
				params["iv"] = Base64.encode64(@iv)
				params["key"] = Base64.encode64(cipher.random_key)
				params = Base64.encode64(key.public_encrypt(JSON.pretty_generate(params)))

				payload = {}
				payload["cmd"] = "diffiehellman"
				payload["key"] = @dh.public_key.to_pem

				pubkey = @dh.pub_key
				payload["pubkey"] = pubkey.to_s

				payload = Base64.encode64(cipher.update(JSON.pretty_generate(payload)) + cipher.final)

				cmd["params"] = params
				cmd["payload"] = payload
				write(@channel, JSON.pretty_generate(cmd))
			elsif (data["cmd"] == "diffiepubkey") then
				pubkey = OpenSSL::BN.new(data["key"], 16)
				@symmkey = @dh.compute_key(pubkey)
				@client.setup_encryption(@symmkey, @iv)

				@client.connect_channel(@channel, Harness::CommandChannelServer.new(@channel, @client))
			else
				puts "Invalid command #{indata}"
				write(@channel, JSON.pretty_generate("cmd" => "upgrade", "to" => "keys"))
			end
		end

		def write(channel, data)
			@client.write(channel, data)
		end
	end

	class KeyClient
		def initialize(channel, client, key)
			@client = client
			@key = key
			@channel = channel
			@on_connect = nil
			@symmkey = nil
			@iv = nil
		end

		def on_connect(&blk)
			@on_connect = blk
		end

		def read(channel, indata)
			data = JSON.parse(indata)
			if (data["cmd"] == "encrypted") then
				key_fingerprint = data["key"]
				raise "Key mismatch" if key_fingerprint != Digest::SHA1.hexdigest(@key.public_key.to_der)
				params = Base64.decode64(data["params"])
				params = @key.private_decrypt(params)
				params = JSON.parse(params)
				cipher = OpenSSL::Cipher::AES256.new(:CBC)
				cipher.decrypt
				cipher.key = Base64.decode64(params["key"])
				@iv = Base64.decode64(params["iv"])
				cipher.iv = @iv


				payload = data["payload"]
				payload = Base64.decode64(payload)
				payload = cipher.update(payload) + cipher.final
				payload = JSON.parse(payload)

				if (payload["cmd"] == "diffiehellman") then
					dh = OpenSSL::PKey::DH.new(payload["key"])
					dh.generate_key!
					@symmkey = dh.compute_key(OpenSSL::BN.new(payload["pubkey"]))

					cmd = {}
					cmd["cmd"] = "diffiepubkey"
					cmd["key"] = dh.pub_key.to_s(16)
					write(@channel, JSON.pretty_generate(cmd))
					@client.setup_encryption(@symmkey, @iv)


					@client.on_drain {
						@client.connect_channel(@channel, Harness::CommandChannelClient.new(@channel, @client))
						@on_connect.call if @on_connect
						@client.on_drain{}
					}					
				else
					raise "Unknown cmd #{indata}"
				end
			else
				raise "Unknown cmd #{indata}"
			end
		end

		def start_key_negotiation
			cmd = {}
			cmd["cmd"] = "key"
			cmd["key"] = @key.public_key.to_pem
			write(@channel, JSON.pretty_generate(cmd))
		end

		def write(channel, data)
			@client.write(channel, data)
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

			if (@dec_cipher) then
				result = @dec_cipher.update(result) if @dec_cipher
			end

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
					break
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

		def setup_encryption(key, iv)
			@enc_cipher = OpenSSL::Cipher.new('aes-256-gcm')
			@enc_cipher.encrypt
			@enc_cipher.key = key
			@enc_cipher.iv = iv

			@dec_cipher = OpenSSL::Cipher.new('aes-256-gcm')
			@dec_cipher.decrypt
			@dec_cipher.key = key
			@dec_cipher.iv = iv

			puts "This connection is now encrypted using 256bit AES"
		end
	end

	class ServerClient < CommonClient
		def initialize(sock)
			@sock = sock
			@write_buffer = ""
			@channels = {}
			@pump = nil
			@verbose = false
			@on_drain = nil
		end

		def on_drain(&blk)
			@on_drain = blk
		end

		def verbose=(val)
			@verbose = val
		end

		def do_write(pump)
			puts "[#{Time.now}] Writing to IO - #{@write_buffer}" if @verbose
			result = @sock.write_nonblock(@write_buffer)
			if (result == @write_buffer.length)
				@write_buffer = ""
				@on_drain.call(self) if @on_drain
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
			if (@enc_cipher) then
				data = @enc_cipher.update(data)
			end
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
			@on_drain = nil
		end

		def on_drain(&blk)
			@on_drain = blk
		end

		def verbose=(val)
			@verbose = val
		end

		def do_write(pump)
			puts "[#{Time.now}] Writing to IO - #{@write_buffer}" if @verbose
			result = @client.write_nonblock(@write_buffer)
			if (result == @write_buffer.length)
				@write_buffer = ""
				@on_drain.call(self) if @on_drain
			else
				@write_buffer = @write_buffer[result..-1]
			end
			@pump = pump
		end

		def write_impl(data)
			if (@enc_cipher) then
				data = @enc_cipher.update(data)
			end
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