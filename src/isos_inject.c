#include <stdlib.h>
#include <stdint.h>
#include <bfd.h>
#include <err.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <unistd.h>

#include "isos_inject.h"

#define BUFFER_SIZE 256
#define GOT_ENTRY 0x110

int is_exploitable(struct arguments *arguments);
int get_first_pt_note_header(struct arguments *arguments);
long append_injection_code(const char code_to_inject_filename[], const char targeted_binary_filename[]);
uintptr_t compute_base_address(uintptr_t base_address, long offset);
int section_header_overwrite(const char binary_filename[], uintptr_t base_address, long offset);
void reorder_section_headers(const char binary_filename[], int inserted_section_index);
void change_section_header_name(const char binary_filename[], const char new_section_header_name[]);
void pt_note_overwrite(const char binary_filename[], int pt_note_index, Elf64_Off injected_code_offset, uintptr_t base_address);
void update_entry_point(const char binary_filename[], Elf64_Addr base_address);
void change_got_entry(const char binary_filename[], Elf64_Addr base_address);

int main(int argc, char **argv)
{
    struct arguments arguments = {
        .elf_filename = NULL,
        .injected_code_filename = NULL,
        .section_name = NULL,
        .base_address = 0,
        .should_modify_entry_point = 0};

    parse_arguments(&arguments, argc, argv);
    if (is_exploitable(&arguments))
    {
        int pt_note_index = get_first_pt_note_header(&arguments);
        printf("PT_NOTE index = %d\n", pt_note_index);
        long offset = append_injection_code(arguments.injected_code_filename, arguments.elf_filename);
        uintptr_t new_base_address = compute_base_address(arguments.base_address, offset);
        printf("0x%lx\n", new_base_address);
        int inserted_section_index = section_header_overwrite(arguments.elf_filename, new_base_address, offset);
        reorder_section_headers(arguments.elf_filename, inserted_section_index);
        change_section_header_name(arguments.elf_filename, arguments.section_name);
        pt_note_overwrite(arguments.elf_filename, pt_note_index, offset, new_base_address);

        if (arguments.should_modify_entry_point)
            update_entry_point(arguments.elf_filename, new_base_address);
        else
            change_got_entry(arguments.elf_filename, new_base_address);
    }
}

/**
 * @brief Checks if the given binary is a 64bits executable ELF file
 *
 * @param arguments structure that contains informations given by the user
 */
int is_exploitable(struct arguments *arguments)
{
    bfd_init();

    bfd *elf_bfd = bfd_openr(arguments->elf_filename, NULL);
    if (elf_bfd == NULL)
        errx(EXIT_FAILURE, "Failed to open elf file using bfd_open()");

    // Check if the file is an ELF binary
    int is_an_ELF_bin = bfd_check_format(elf_bfd, bfd_object);
    int is_64bits = bfd_get_arch_size(elf_bfd) == 64;
    int is_executable = bfd_get_file_flags(elf_bfd) & EXEC_P;

    bfd_close(elf_bfd);

    if (is_an_ELF_bin && is_64bits && is_executable)
        return 1;
    else
        return 0;
}

/**
 * @brief Get the first pt note header object
 *
 * @param arguments
 * @return The index of the first pt note header, -1 if there is none
 */
int get_first_pt_note_header(struct arguments *arguments)
{
    FILE *fd = fopen(arguments->elf_filename, "r");
    if (fd == NULL)
        errx(EXIT_FAILURE, "Error on fopen()");

    int int_fd = fileno(fd);
    if (int_fd == -1)
    {
        perror("Failed to get fd associated to the given file");
        goto _cleanup_fd;
    }

    struct stat binary_info;
    if (fstat(int_fd, &binary_info) == -1)
    {
        perror("Unable to get binary stats");
        goto _cleanup_fd;
    }

    Elf64_Ehdr *mapped_elf_file = mmap(NULL, binary_info.st_size, PROT_READ, MAP_PRIVATE, int_fd, 0);
    if (mapped_elf_file == NULL)
    {
        perror("Unable to mmap the binary");
        goto _cleanup_fd;
    }

    // Get the program headers
    // We cast at first he mapped_elf_file ptr to char* so as to be able to add the offset without problems
    Elf64_Phdr *program_headers = (Elf64_Phdr *)((uintptr_t)mapped_elf_file + mapped_elf_file->e_phoff);
    for (int i = 0; i < mapped_elf_file->e_phnum; i++)
    {
        // Get the p_type field
        uint32_t p_type = program_headers->p_type;

        // Check if the p_type field is PT_NOTE
        if (p_type == PT_NOTE)
        {
            // Close the file descriptor
            if (fclose(fd) == EOF)
                perror("Failed to close the file descriptor");
            // Unmap the binary file from memory
            if (munmap(mapped_elf_file, binary_info.st_size) == -1)
                err(EXIT_FAILURE, "unmaping failed");
            return i;
        }
        // Move to the next program header
        program_headers++;
    }

    // Unmap the binary file from memory
    if (munmap(mapped_elf_file, binary_info.st_size) == -1)
    {
        perror("unmaping failed");
        goto _cleanup_fd;
    }

    // Close the file descriptor
    if (fclose(fd) == EOF)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");

    return -1;
_cleanup_fd:
    // Close the file descriptor
    if (fclose(fd) == EOF)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return -1;
}

/**
 * @brief Append the code to inject at the end of the targeted binary
 *
 * @param code_to_inject_filename Name of the file that contains the assembly to append
 * @param targeted_binary_filename Name of the targeted binary
 * @return Offset where the code bytes have been written
 */
long append_injection_code(const char code_to_inject_filename[], const char targeted_binary_filename[])
{
    // Open each file
    FILE *code_to_inject_fd = fopen(code_to_inject_filename, "rb");
    if (code_to_inject_fd == NULL)
        errx(EXIT_FAILURE, "Failed to open the code to inject");

    FILE *targeted_binary_fd = fopen(targeted_binary_filename, "ab");
    if (targeted_binary_fd == NULL)
    {
        perror("Failed to open the targeted binary");
        goto _cleanup_code_to_inject;
    }

    long offset = ftell(targeted_binary_fd);

    char buffer[BUFFER_SIZE];
    size_t data_chunks;
    while ((data_chunks = fread(buffer, 1, sizeof(buffer), code_to_inject_fd)) > 0)
        fwrite(buffer, 1, data_chunks, targeted_binary_fd);

    // Close all files before exiting

    if (fclose(targeted_binary_fd) == EOF)
    {
        perror("Failed to close targeted_binary_fd");
        goto _cleanup_code_to_inject;
    }

    if (fclose(code_to_inject_fd) == EOF)
        errx(EXIT_FAILURE, "Failed to close code_to_inject_fd");

    return offset;

_cleanup_code_to_inject:
    if (fclose(code_to_inject_fd) == EOF)
        errx(EXIT_FAILURE, "Failed to close code_to_inject_fd");
    return -1;
}

/**
 * @brief The base address and the offset needs to be congruent with 0 mod 4096
 *
 * @param base_address base_address given by the user
 * @param offset offset between the address of our program and the beginning of the file
 */
uintptr_t compute_base_address(uintptr_t base_address, long offset)
{
    base_address += (offset - base_address) % 4096;
    return base_address;
}

/**
 * @brief Overwrite the .note.ABI-tag section header to adapt it to our injected code
 *
 * @param binary_filename
 * @param base_address
 * @param offset
 */
int section_header_overwrite(const char binary_filename[], uintptr_t base_address, long offset)
{
    int fd = open(binary_filename, O_RDWR);
    if (fd == -1)
        errx(EXIT_FAILURE, "Error on open()");

    struct stat binary_info;
    if (fstat(fd, &binary_info) == -1)
    {
        perror("Unable to get binary stats");
        goto _cleanup_fd;
    }

    Elf64_Ehdr *mapped_elf_file = mmap(NULL, binary_info.st_size, (PROT_WRITE | PROT_READ), MAP_SHARED, fd, 0);
    if (mapped_elf_file == MAP_FAILED)
    {
        perror("Unable to mmap the binary");
        goto _cleanup_fd;
    }

    // Get the section headers
    Elf64_Shdr *section_headers = (Elf64_Shdr *)((uintptr_t)mapped_elf_file + mapped_elf_file->e_shoff);
    int inserted_section_index = 0;
    // Loop on all the section headers
    for (int i = 0; i < mapped_elf_file->e_shnum; i++)
    {
        Elf64_Shdr *shdr_strtab = (Elf64_Shdr *)((uintptr_t)mapped_elf_file + mapped_elf_file->e_shoff + mapped_elf_file->e_shstrndx * mapped_elf_file->e_shentsize);
        const char *name = (const char *)mapped_elf_file + shdr_strtab->sh_offset + section_headers->sh_name;
        if (strcmp(name, ".note.ABI-tag") == 0)
        {
            printf(".note-ABI-tag\n");
            section_headers->sh_type = SHT_PROGBITS;
            section_headers->sh_addr = base_address;
            section_headers->sh_offset = offset;
            section_headers->sh_size = binary_info.st_size;
            section_headers->sh_addralign = 16;
            section_headers->sh_flags = SHF_EXECINSTR;
            if (msync(mapped_elf_file, binary_info.st_size, MS_SYNC) == -1)
            {
                perror("Error on msync");
                goto _cleanup_mmap;
            }
            inserted_section_index = i;
        }
        section_headers++;
    }
    if (munmap(mapped_elf_file, binary_info.st_size) == -1)
        goto _cleanup_fd;

    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return inserted_section_index;

_cleanup_mmap:
    // Unmap the binary file from memory
    if (munmap(mapped_elf_file, binary_info.st_size) == -1)
        perror("unmaping failed");
_cleanup_fd:
    // Close the file descriptor
    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return -1;
}

/**
 * @brief Redorder the sections headers in growing order
 *
 * @param binary_filename filename of the binary to reorder
 */
void reorder_section_headers(const char binary_filename[], int inserted_section_index)
{
    int fd = open(binary_filename, O_RDWR);
    if (fd == -1)
        errx(EXIT_FAILURE, "Failed to open the binary file");

    struct stat binary_info;
    if (fstat(fd, &binary_info) == -1)
    {
        perror("Failed to get binary stats");
        goto _cleanup_fd;
    }

    Elf64_Ehdr *mapped_elf_file = mmap(NULL, binary_info.st_size, (PROT_WRITE | PROT_READ), MAP_SHARED, fd, 0);
    if (mapped_elf_file == MAP_FAILED)
    {
        perror("Unable to mmap the binary");
        goto _cleanup_fd;
    }

    Elf64_Shdr *section_headers = (Elf64_Shdr *)((uintptr_t)mapped_elf_file + mapped_elf_file->e_shoff);

    int starting_index = inserted_section_index;
    // Sort to the left
    while (((inserted_section_index - 1) >= 0) &&                                                                 // Not the 1st section header
           section_headers[inserted_section_index].sh_addr < section_headers[inserted_section_index - 1].sh_addr) // Lower than the previous one
    {
        // swap
        Elf64_Shdr tmp = section_headers[inserted_section_index];
        section_headers[inserted_section_index] = section_headers[inserted_section_index - 1];
        section_headers[inserted_section_index - 1] = tmp;

        inserted_section_index--;
    }

    // Sort to the right
    while (((inserted_section_index + 1) < mapped_elf_file->e_shnum) &&                                             // Not at the last position
           (section_headers[inserted_section_index + 1].sh_addr != 0) &&                                            // Not on a special addr
           (section_headers[inserted_section_index].sh_addr > section_headers[inserted_section_index + 1].sh_addr)) // upper than the next
    {
        // swap
        Elf64_Shdr tmp = section_headers[inserted_section_index];
        section_headers[inserted_section_index] = section_headers[inserted_section_index + 1];
        section_headers[inserted_section_index + 1] = tmp;

        inserted_section_index++;
    }

    // parse from default inserted_section_index to the last position and modify things
    if (inserted_section_index < starting_index) // Swapped to the left
    {
        for (int i = starting_index; i > inserted_section_index; i--)
        {
            if (section_headers[i].sh_link > 0)
                section_headers[i].sh_link++;
        }
    }
    else if (inserted_section_index > starting_index) // Swapped to the right
    {
        for (int i = starting_index; i < inserted_section_index; i++)
        {
            if (section_headers[i].sh_link > 0)
                section_headers[i].sh_link--;
        }
    }

    if (munmap(mapped_elf_file, binary_info.st_size) == -1)
        goto _cleanup_fd;

    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return;

_cleanup_fd:
    // Close the file descriptor
    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
}

/**
 * @brief Change the .note_ABI-tag section name to the one given into the parameters
 *
 * @param binary_filename Binary to modify
 * @param new_section_header_name New name to give to the section header
 */
void change_section_header_name(const char binary_filename[], const char new_section_header_name[])
{
    if (strlen(new_section_header_name) > strlen(".note-ABI-tag"))
        errx(EXIT_FAILURE, "The new section name needs to be shorter than .note-ABI-tag");

    int fd = open(binary_filename, O_RDWR);
    if (fd == -1)
        errx(EXIT_FAILURE, "Error on open()");

    struct stat binary_info;
    if (fstat(fd, &binary_info) == -1)
    {
        perror("Unable to get binary stats");
        goto _cleanup_fd;
    }

    Elf64_Ehdr *mapped_elf_file = mmap(NULL, binary_info.st_size, (PROT_WRITE | PROT_READ), MAP_SHARED, fd, 0);
    if (mapped_elf_file == MAP_FAILED)
    {
        perror("Unable to mmap the binary");
        goto _cleanup_fd;
    }

    // Get the section headers
    Elf64_Shdr *section_headers = (Elf64_Shdr *)((uintptr_t)mapped_elf_file + mapped_elf_file->e_shoff);
    // Loop on all the section header
    for (int i = 0; i < mapped_elf_file->e_shnum; i++)
    {
        Elf64_Shdr *shdr_strtab = (Elf64_Shdr *)((uintptr_t)mapped_elf_file + mapped_elf_file->e_shoff + mapped_elf_file->e_shstrndx * mapped_elf_file->e_shentsize);
        char *name = (char *)mapped_elf_file + shdr_strtab->sh_offset + section_headers->sh_name;
        if (strcmp(name, ".note.ABI-tag") == 0)
        {
            size_t current_name = strlen(name);
            strncpy((char *)name, new_section_header_name, current_name);

            if (msync(mapped_elf_file, binary_info.st_size, MS_SYNC) == -1)
            {
                perror("Error on msync");
                goto _cleanup_mmap;
            }
        }
        section_headers++;
    }
    if (munmap(mapped_elf_file, binary_info.st_size) == -1)
        goto _cleanup_fd;

    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return;
_cleanup_mmap:
    // Unmap the binary file from memory
    if (munmap(mapped_elf_file, binary_info.st_size) == -1)
        perror("unmaping failed");
_cleanup_fd:
    // Close the file descriptor
    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return;
}

/**
 * @brief Overwrite the pt_note program header with the informations of the injected code
 *
 * @param binary_filename
 * @param pt_note_index
 * @param injected_code_offset
 * @param base_address
 */
void pt_note_overwrite(const char binary_filename[], int pt_note_index, Elf64_Off injected_code_offset, uintptr_t base_address)
{
    int fd = open(binary_filename, O_RDWR);
    if (fd == -1)
        errx(EXIT_FAILURE, "Error on open()");

    struct stat binary_info;
    if (fstat(fd, &binary_info) == -1)
    {
        perror("Unable to get binary stats");
        goto _cleanup_fd;
    }

    Elf64_Ehdr *mapped_elf_file = mmap(NULL, binary_info.st_size, (PROT_WRITE | PROT_READ), MAP_SHARED, fd, 0);
    if (mapped_elf_file == MAP_FAILED)
    {
        perror("Unable to mmap the binary");
        goto _cleanup_fd;
    }

    Elf64_Phdr *program_headers = (Elf64_Phdr *)((uintptr_t)mapped_elf_file + mapped_elf_file->e_phoff);

    // Modify the values of the pt_note program header
    program_headers[pt_note_index].p_type = PT_LOAD;
    program_headers[pt_note_index].p_offset = injected_code_offset;
    program_headers[pt_note_index].p_vaddr = base_address;
    program_headers[pt_note_index].p_paddr = base_address;
    program_headers[pt_note_index].p_flags = PF_X | PF_R;
    program_headers[pt_note_index].p_align = 0x1000;

    if (munmap(mapped_elf_file, binary_info.st_size) == -1)
        goto _cleanup_fd;

    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return;

_cleanup_fd:
    // Close the file descriptor
    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return;
}

/**
 * @brief Change the entry point value in the executable headers of the binary to the given address
 *
 * @param binary_filename
 * @param base_address
 */
void update_entry_point(const char binary_filename[], Elf64_Addr base_address)
{
    int fd = open(binary_filename, O_RDWR);
    if (fd == -1)
        errx(EXIT_FAILURE, "Error on open()");

    struct stat binary_info;
    if (fstat(fd, &binary_info) == -1)
    {
        perror("Unable to get binary stats");
        goto _cleanup_fd;
    }

    Elf64_Ehdr *mapped_elf_file = mmap(NULL, binary_info.st_size, (PROT_WRITE | PROT_READ), MAP_SHARED, fd, 0);
    if (mapped_elf_file == MAP_FAILED)
    {
        perror("Unable to mmap the binary");
        goto _cleanup_fd;
    }

    // Update the entry point in the ELF header
    mapped_elf_file->e_entry = base_address;
    printf("New entry point : %lx", mapped_elf_file->e_entry);

    if (munmap(mapped_elf_file, binary_info.st_size) == -1)
        goto _cleanup_fd;

    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return;

_cleanup_fd:
    // Close the file descriptor
    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return;
}

void change_got_entry(const char binary_filename[], Elf64_Addr base_address)
{
    int fd = open(binary_filename, O_RDWR);
    if (fd == -1)
        errx(EXIT_FAILURE, "Error on open()");

    struct stat binary_info;
    if (fstat(fd, &binary_info) == -1)
    {
        perror("Unable to get binary stats");
        goto _cleanup_fd;
    }

    Elf64_Ehdr *mapped_elf_file = mmap(NULL, binary_info.st_size, (PROT_WRITE | PROT_READ), MAP_SHARED, fd, 0);
    if (mapped_elf_file == MAP_FAILED)
    {
        perror("Unable to mmap the binary");
        goto _cleanup_fd;
    }

    Elf64_Shdr *section_headers = (Elf64_Shdr *)((uintptr_t)mapped_elf_file + mapped_elf_file->e_shoff);
    Elf64_Shdr *shdr_strtab = (Elf64_Shdr *)((uintptr_t)section_headers + mapped_elf_file->e_shstrndx * mapped_elf_file->e_shentsize);
    for (int i = 0; i < mapped_elf_file->e_shnum; i++)
    {
        const char *name = (const char *)mapped_elf_file + shdr_strtab->sh_offset + section_headers->sh_name;
        if (strcmp(name, ".got.plt") == 0)
        {
            printf("GOT it\n");
            Elf64_Addr *content_ptr = (Elf64_Addr *)((uintptr_t)mapped_elf_file + section_headers->sh_offset + GOT_ENTRY);
            *content_ptr = base_address;
            break;
        }
        section_headers++;
    }

    if (munmap(mapped_elf_file, binary_info.st_size) == -1)
        goto _cleanup_fd;

    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return;

_cleanup_fd:
    // Close the file descriptor
    if (close(fd) == -1)
        errx(EXIT_FAILURE, "Failed to close the file descriptor");
    return;
}