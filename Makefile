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

all: $(NAME)

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
	$(call remove_target,.vscode)
	$(call remove_target,garbage/a.out)
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
	@echo "CompileFlags:" > .clangd
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

define compile_from_source
    @wget -O source.tar.gz $(1)
    @mkdir source_dir && tar xvf source.tar.gz -C source_dir --strip-components=1
    @cd source_dir && ./configure --prefix=$$HOME/.local && make && make install
    @rm -rf source_dir source.tar.gz
endef

install_libpcap: clangd
	@mkdir -p $$HOME/.local/bin $$HOME/.local/include $$HOME/.local/lib $$HOME/.local/share
	$(call compile_from_source,https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.xz)
	$(call compile_from_source,https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz)
	$(call compile_from_source,https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz)
	$(call compile_from_source,https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz)

uninstall_libpcap:
	@rm -rf $$HOME/.local/bin/m4
	@rm -rf $$HOME/.local/bin/flex
	@rm -rf $$HOME/.local/bin/flex++
	@rm -rf $$HOME/.local/include/FlexLexer.h
	@rm -rf $$HOME/.local/bin/bison
	@rm -rf $$HOME/.local/share/bison
	@rm -rf $$HOME/.local/*/*pcap*

.PHONY: all clean fclean re help vagrant_destroy install_libpcap uninstall_libpcap