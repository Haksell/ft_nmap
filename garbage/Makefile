run_ldev: # TODO: -Wall -Wextra -Werror
	@cc -std=gnu17 -g3 -fsanitize=address,undefined -I$$HOME/.local/include ldev.c -L$$HOME/.local/lib -lpcap
	@LD_LIBRARY_PATH=$$HOME/.local/lib ./a.out