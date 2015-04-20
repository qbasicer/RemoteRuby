require 'socket'
require 'json'
require 'open3'
require 'pty'
require 'digest'
require 'openssl'
require 'base64'
require 'io/console'

module Harness

	class IOPump
		def initialize()
			@io_list = []
			@running = false
			@verbose = false
			@wc = WakeClient.new
			add(@wc)
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

		def wake
			@wc.wake
		end

		def run
			@running = true
			while (@running) do
				@io_list.delete_if{|sock| 
					r = false
					begin
						r = (sock.closed? || sock.client.closed?)
					rescue Exception=>e
						puts "#{e.message} on #{sock}"
						puts "#{e.backtrace.join("\n\t")}"
					end
					r
				}
				break if @io_list.size == 1

				write_list = @io_list.select{|sock| sock.writeable?}
				read_list = @io_list.select{|sock| sock.readable?}
				rl, wl = IO.select(read_list, write_list, [], 1)
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
				@io_list.select{|dev| dev.respond_to?(:tick)}.each{|dev| dev.tick}
			end
		end

		def stop
			@running = false
		end
	end

	class WakeClient
		def initialize
			rd, wr = IO.pipe
			@rd = rd
			@wr = wr
		end

		def wake
			@wr.write("\0")
		end

		def client
			self
		end

		def do_read(pump)
			begin
				r = @rd.read_nonblock(1024)
			rescue Exception=>e

			end
		end

		def writeable?
			false
		end

		def closed?
			false
		end

		def readable?
			true
		end

		def to_io
			@rd
		end
	end

	class Server
		def initialize(port)
			@server = TCPServer.new port

			@on_connect = []
			@verbose = false
		end

		def closed?
			false
		end

		def writeable?
			false
		end

		def client
			self
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
			@last = Time.now
			@last_pong = Time.now
		end

		def tick
			if (Time.now - @last > 5) then
				@last = Time.now
				write(0, JSON.pretty_generate({"cmd" => "ping"}))
			end
			if (Time.now - @last_pong > 15) then
				puts "No pong for 15s, goodbye"
				@client.close
			end
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
				pipe = PipeToChannel.new(output, stdout_channel, @client)
				@client.connect_channel(1, pipe)
				@client.pump.add(pipe)

				odata["cmd"] = "newchannel"
				odata["name"] = "stdin"
				odata["type"] = "in"
				odata["index"] = 2
				write(0, JSON.pretty_generate(odata))

				pipe = ChannelToPipe.new(input, @client)
				@client.connect_channel(2, pipe)
				@client.pump.add(pipe)

				odata["cmd"] = "newchannel"
				odata["name"] = "ptycntrl"
				odata["type"] = "pty"
				odata["index"] = 3
				write(0, JSON.pretty_generate(odata))

				puts "Creating new channel"

				pipe = PtyCommandChannel.new(input: input, output: output, pid: pid, client: @client)
				@client.connect_channel(3, pipe)
			elsif (data["cmd"] == "closechannel") then
				@client.drop_channel(data["index"])
			elsif (data["cmd"] == "ping") then
				write(0, JSON.pretty_generate({"cmd" => "pong"}))
			elsif (data["cmd"] == "pong") then
				@last_pong = Time.now
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
			@last = Time.now
			@last_pong = Time.now
		end

		def tick
			if (Time.now - @last > 5) then
				@last = Time.now
				write(0, JSON.pretty_generate({"cmd" => "ping"}))
			end
			if (Time.now - @last_pong > 15) then
				puts "No pong for 15s, goodbye"
				@client.close
			end
		end

		def read(channel, indata)
			data = JSON.parse(indata)
			if (data["cmd"] == "newchannel") then
				pipe = $stdout if data["name"] == "stdout"
				pipe = $stderr if data["name"] == "stderr"
				pipe = $stdin if data["name"] == "stdin"

				if (data["type"] == "out") then
					#puts "***** CONNECTING NEW PIPE FOR #{data["name"]}"
					
					pipe = ChannelToPipe.new(pipe, @client)

					pipe.verbose = true

					@client.connect_channel(data["index"], pipe)
					@client.pump.add(pipe)
				elsif (data["type"] == "in") then
					#puts "***** CONNECTING NEW PIPE FOR #{data["name"]}"
					channel = IOChannel.new(data["index"], @client)
					pipe = PipeToChannel.new(pipe, channel, @client)
					@client.connect_channel(data["index"], pipe)
					@client.pump.add(pipe)
				elsif (data["type"] == "pty")
					pipe = PtyControlChannel.new(data["index"], client: @client)
					@client.connect_channel(data["index"], pipe)
				end
			elsif (data["cmd"] == "closechannel") then
				@client.drop_channel(data["index"])

				if (data["index"] > 0) then
					@client.deliver_signal("TERM")
					@client.close_channel(1) if data["index"] != 1
					@client.close_channel(2) if data["index"] != 2
					@client.close_channel(3) if data["index"] != 3
				end

				if (@client.channels.size == 1) then
					@client.close_channel(0)
				end
			elsif (data["cmd"] == "ping") then
				write(0, JSON.pretty_generate({"cmd" => "pong"}))
			elsif (data["cmd"] == "pong") then
				@last_pong = Time.now
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

	class PtyCommandChannel
		def initialize(input: nil, output: nil, pid: nil, client: nil)
			@channel = nil
			@input = input
			@output = output
			@pid = pid
			@client = client
		end

		def on_channel_connect(client, channel)
			@client = client
			@channel = channel
			client.write(channel, JSON.pretty_generate({"cmd" => "gettermsize"}))
		end

		def read(channel, data)
			data = JSON.parse(data)
			if (data["cmd"] == "deliversignal") then
				s =  "[SRVR] Sending #{data["signal"]} to #{@pid}\n" 
				print s
				@client.write(1, s) unless @client.channels[1].nil?
				Process.kill(data["signal"], @pid)
			elsif (data["cmd"] == "settermsize") then
				@output.winsize = data["size"]
			end
		end
	end

	class PtyControlChannel
		def initialize(channel, client: nil)
			@channel = channel
			@client = client
		end

		def read(channel, data)
			data = JSON.parse(data)
			if (data["cmd"] == "gettermsize") then
				send_term_size
			end
		end

		def send_term_size
			@client.write(@channel, JSON.pretty_generate({"cmd" => "settermsize", "size" => $stdout.winsize}))
		end

		def deliver_signal(sig)
			@client.write(@channel, JSON.pretty_generate({"cmd" => "deliversignal", "signal" => sig.to_s.upcase}))
		end
	end

	class ChannelToPipe
		def initialize(io, client, insert_cr: false, output_file: nil)
			@io = io
			@write_buffer = ""
			@insert_cr = insert_cr
			@f = nil
			if (output_file) then
				@f = File.open(output_file, "w")
				@f.sync = true
			end
			@verbose = false
			@closed = false
			@client = client
		end

		def client
			@client
		end

		def closed?
			@closed
		end

		def close
			@closed = true
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

		def channel
			@channel
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
		def initialize(io, channel, client)
			@io = io
			@channel = channel
			@closed = false
			@client = client
		end

		def client
			@client
		end

		def closed?
			@closed
		end

		def close
			@closed = true
		end

		def readable?
			true
		end

		def do_read(pump)
			begin
				result = to_io.read_nonblock(1024)
				@channel.write(result)
				#puts "CHAN #{@channel} READ #{result}"
			rescue EOFError=>e
				@channel.close(self)				
			rescue Exception=>e
				puts "Channel closed #{@channel} (#{@channel.channel}) closed!"
				puts "#{e.class} - #{e.message}"
				puts "#{e.backtrace.join("\n\t")}"

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

		def closed?
			@closed
		end


		def tick
			@channels.each{|chan, channel|
				if (channel.respond_to?(:tick)) then
					channel.tick
				end
			}			
		end

		def write(channel, data)
			if (@channels[channel].nil?) then
				raise "Cannot write #{data.length}B (#{data}) to #{channel}"
			end
			newdata = [channel].pack("S")

			newdata = "#{newdata}#{data}"

			length = [newdata.length].pack("L")

			write_impl("#{length}#{newdata}")
		end

		def do_read(pump)
			return if closed?
			begin
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
			rescue EOFError=>e
				@closed = true
			end
		end

		def read_channel(channel, data)
			@channels ||= {}
			raise "No connected channel #{channel} -  data is #{data} (#{data.length})" unless @channels.include?(channel)
			@channels[channel].read(channel, data)
		end

		def channels
			@channels
		end

		def close_channel(channelno)
			@channels ||= {}
			@channels[0].send_closed_channel(channelno)
			drop_channel(channelno)
		end

		def drop_channel(channelno)
			@channels ||= {}
			c = @channels[channelno]

			pump.remove(c) unless c.nil?

			@channels.delete(channelno)

			if (@channels.empty?) then
				@closed = true
				to_io.close
			end
		end

		def client
			self
		end

		def connect_channel(channelno, channel)
			@channels ||= {}
			@channels[channelno] = channel
			channel.on_channel_connect(self, channelno) if channel.respond_to?(:on_channel_connect)
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
			@closed = false
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
			@on_drain = []
			@closed = false
		end

		def on_drain(&blk)
			@on_drain.push blk
		end

		def prompt

		end

		def deliver_signal(signal)
			pty = channels[3]
			return false if pty.nil?
			pty.deliver_signal(signal)
		end

		def verbose=(val)
			@verbose = val
		end

		def do_write(pump)
			puts "[#{Time.now}] Writing to IO - #{@write_buffer}" if @verbose
			result = @client.write_nonblock(@write_buffer)
			if (result == @write_buffer.length)
				@write_buffer = ""
				while (!@on_drain.empty?) do
					blk = @on_drain.shift
					blk.call(self)
				end
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