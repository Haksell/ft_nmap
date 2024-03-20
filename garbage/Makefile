run:
	@cc -std=gnu17 -g3 -Wall -Wextra -Werror -fsanitize=address,undefined -I$$HOME/.local/include $(src) -L$$HOME/.local/lib -lpcap -lpthread
	@LD_LIBRARY_PATH=$$HOME/.local/lib ./a.out $(args)