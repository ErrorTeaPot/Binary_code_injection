#include "isos_inject.h"
#include <argp.h>
#include <stdlib.h>
#include <err.h>

static char doc[] =
    "ISOS project";

static char args_doc[] = "-e <elf_file> -c <code_section> -b <base_address> -m <modify-entry>";

/**
 * @brief Describes the options our program needs to understand
 *
 */
static struct argp_option options[] = {
    {"elf", 'e', "ELF_FILE", 0, "The ELF file to be analyzed", 0},
    {"code", 'c', "CODE_FILE", 0, "The binary file containing the machine code to be injected", 0},
    {"section", 's', "SECTION_NAME", 0, "The name of the newly created section", 0},
    {"base", 'b', "BASE_ADDRESS", 0, "The base address of the injected code", 0},
    {"modify-entry", 'm', 0, 0, "Modify the entry function or not", 0},
    {0}};

/**
 * @brief Function that stores the argument values into the structure
 *
 * @param key option character given by the user
 * @param arg value associated with the key given by the user
 * @param state Value required by argp
 * @return error_t
 */
static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
    case 'e':
        //I use directly = since arguments are stored into the main stack frame
        arguments->elf_filename = arg;
        break;
    case 'c':
        arguments->injected_code_filename = arg;
        break;
    case 's':
        arguments->section_name = arg;
        break;
    case 'b':
        arguments->base_address = strtoul(arg, NULL, 16);
        break;
    case 'm':
        arguments->should_modify_entry_point = 1;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return EXIT_SUCCESS;
}

static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

/**
 * @brief Apply the argp function to the arguments given by the user
 *
 * @param arguments Structure that will take the values of the arguments
 * @param argc number of parameters given by the user
 * @param argv parameters given by the user
 */
void parse_arguments(struct arguments *arguments, int argc, char **argv)
{
    // Parse arguments
    error_t return_code = argp_parse(&argp, argc, argv, 0, 0, arguments);
    if (return_code != 0)
        errx(EXIT_FAILURE, "Bad return code for argp_parse()");
}