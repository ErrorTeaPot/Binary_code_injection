#include <stdint.h>

/**
 * @brief Structure that will contain the values of the arguments given with our options
 *
 */
struct arguments
{
    const char *elf_filename;
    const char *injected_code_filename;
    const char *section_name;
    uintptr_t base_address;
    int should_modify_entry_point;
};

void parse_arguments(struct arguments *arguments, int argc, char **argv);