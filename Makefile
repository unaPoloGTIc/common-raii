all:  commons runtests

commons:
	g++ -g -std=c++17 -fPIC -c common-raii.cpp -Wl,--no-undefined

unittests: commons
	g++ -g unittests.cpp -o unittests common-raii.o -std=c++17 -Wl,--no-undefined -lgtest -lgmock -lpthread -lpam -lmicrohttpd `gpgme-config --cflags --libs` `curl-config --libs`

run-unit-tests: unittests
	./unittests

run-leak-tests: unittests
	valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=all --track-origins=yes -v ./unittests

runtests: run-unit-tests run-leak-tests

clean:
	rm *.o unittests
