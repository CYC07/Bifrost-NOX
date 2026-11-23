all: firewall_engine

firewall_engine: firewall_engine.cpp brain_client.hpp
	g++ -std=c++17 -Wall -Wextra -o firewall_engine firewall_engine.cpp -lnetfilter_queue -lnfnetlink -lzmq

# Test driver for the brain client (built and run by tests/test_firewall_engine_brain.py)
brain_probe: brain_probe.cpp brain_client.hpp
	g++ -std=c++17 -Wall -Wextra -Werror -o brain_probe brain_probe.cpp -lzmq

clean:
	rm -f firewall_engine brain_probe

.PHONY: all clean
