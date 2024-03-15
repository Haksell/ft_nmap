NAME := ft_nmap
INCLUDE_DIR := include
HEADER := $(INCLUDE_DIR)/ft_nmap.h

PATH_SRCS := srcs
PATH_OBJS := objs

SRCS := $(wildcard $(PATH_SRCS)/*.c)
OBJS := $(SRCS:$(PATH_SRCS)/%.c=$(PATH_OBJS)/%.o)

CC := cc -std=gnu17 -Wall -Wextra -Werror -g3 -fsanitize=address,undefined -I$(INCLUDE_DIR)

RESET := \033[0m
RED := \033[1m\033[31m
GREEN := \033[1m\033[32m
PURPLE := \033[1m\033[35m

define remove_target
@if [ -e "$(1)" ]; then \
	rm -rf "$(1)"; \
	echo "$(RED)[X] $(1) removed.$(RESET)"; \
fi
endef

all: $(NAME) clangd

$(PATH_OBJS):
	@mkdir -p $(sort $(dir $(OBJS)))

$(OBJS): $(PATH_OBJS)/%.o: $(PATH_SRCS)/%.c $(HEADER)
	@mkdir -p $(PATH_OBJS)
	@$(CC) -c $< -o $@
	@echo "$(GREEN)+++ $@$(RESET)"

$(NAME): $(OBJS)
	@$(CC) $(OBJS) -o $@
	@echo "$(PURPLE)$@ is compiled.$(RESET)"

clean:
	@rm -rf .vscode
	$(call remove_target,$(PATH_OBJS))

fclean: clean
	$(call remove_target,$(NAME))
	$(call remove_target,.clangd)

re: fclean
	@$(MAKE) -s $(NAME)

help: all
	@./$(NAME) --version --help

vagrant_destroy:
	vagrant destroy -f
	rm -rf .vagrant
	rm -rf *VBox*.log

clangd:
	@echo "CompileFlags:" >> .clangd
	@echo "    Add:" >> .clangd
	@echo "        - '-x'" >> .clangd
	@echo "        - 'c-header'" >> .clangd
	@echo "        - '-std=gnu17'" >> .clangd
	@echo "        - '-Iinclude'" >> .clangd
	@echo "        - '-I../include'" >> .clangd
	@echo "        - '-I$$HOME/.local/include'" >> .clangd
	@echo "        - '-L$$HOME/.local/lib'" >> .clangd
	@echo "        - '-lpcap'" >> .clangd

.clangd: clangd

install_libpcap:
	@mkdir -p $$HOME/.local/bin $$HOME/.local/include $$HOME/.local/lib $$HOME/.local/share
	@echo $$HOME

uninstall_libpcap:
	@echo TODO

.PHONY: all clean fclean re help vagrant_destroy install_libpcap uninstall_libpcap