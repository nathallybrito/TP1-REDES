.PHONY: run_serv run_cli

run_serv:
	python3 srv.py $(arg1) $(arg2) $(arg3)

run_cli:
	python3 cli.py $(arg1) $(arg2)
