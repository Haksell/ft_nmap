NAME := ft_nmap
HEADER := ft_nmap.h

PATH_SRCS := srcs
PATH_OBJS := objs

SRCS := $(wildcard $(PATH_SRCS)/*.c)
OBJS := $(SRCS:$(PATH_SRCS)/%.c=$(PATH_OBJS)/%.o)

CC := cc -std=gnu17 -Wall -Wextra -Werror -g3 -fsanitize=address,undefined

RESET := \033[0m
RED := \033[1m\033[31m
GREEN := \033[1m\033[32m
BLUE := \033[1m\033[34m
PINK := \033[1m\033[35m

define remove_target
@if [ -e "$(1)" ]; then \
	rm -rf "$(1)"; \
	echo "$(RED)[X] $(1) removed.$(RESET)"; \
fi
endef

all: $(NAME)

$(PATH_OBJS):
	@mkdir -p $(sort $(dir $(OBJS)))

$(OBJS): $(PATH_OBJS)/%.o: $(PATH_SRCS)/%.c $(HEADER)
	@mkdir -p $(PATH_OBJS)
	@$(CC) -c $< -o $@
	@echo "$(BLUE)+++ $@$(RESET)"

$(NAME): $(OBJS)
	@$(CC) $(OBJS) -o $@
	@echo "$(PINK)$@ is compiled.$(RESET)"

clean:
	@rm -rf .vscode
	$(call remove_target,$(PATH_OBJS))

fclean: clean
	$(call remove_target,$(NAME))

re: fclean
	@$(MAKE) -s $(NAME)

run: all
	@./$(NAME) --help

rerun: fclean run

.PHONY: all clean fclean re run rerun