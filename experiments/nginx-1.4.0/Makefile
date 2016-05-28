
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile
	$(MAKE) -f objs/Makefile manpage

install:
	$(MAKE) -f objs/Makefile install

upgrade:
	/home/klu/projects/RuntimeASLR/experiments/nginx-1.4.0/prefix/sbin/nginx -t

	kill -USR2 `cat /home/klu/projects/RuntimeASLR/experiments/nginx-1.4.0/prefix/logs/nginx.pid`
	sleep 1
	test -f /home/klu/projects/RuntimeASLR/experiments/nginx-1.4.0/prefix/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/klu/projects/RuntimeASLR/experiments/nginx-1.4.0/prefix/logs/nginx.pid.oldbin`
