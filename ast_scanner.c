#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tree_sitter/api.h>

TSLanguage *tree_sitter_c(void);

typedef struct {
    const char *identifier;
    const char *risk;
    const char *message;
    const char *replacement;
} CryptoRule;

CryptoRule rules[] = {
    {"RSA_generate_key_ex", "HIGH",     "RSA key generation detected (vulnerable to Shor's algorithm).", "ML-KEM / ML-DSA"},
    {"EC_KEY_new_by_curve_name", "HIGH", "ECC curve initialization detected (vulnerable to Shor's algorithm).", "ML-KEM / ML-DSA"},
    {"EVP_PKEY_RSA",        "HIGH",     "OpenSSL RSA PKEY detected.", "ML-KEM / ML-DSA"},
    {"EVP_aes_128_cbc",     "MODERATE", "AES-128 detected (vulnerable to Grover's algorithm).", "AES-256 / PQC"},
    {"EVP_aes_256_cbc",     "LOWER",    "AES-256 detected.", "Retain (Quantum-resistant)"},
    {"EVP_sha256",          "LOWER",    "SHA-256 detected.", "Retain (Quantum-resistant)"}
};

int num_rules = sizeof(rules) / sizeof(rules[0]);

void traverse_ast(TSNode node, const char *source_code) {
    const char *type = ts_node_type(node);

    if (strcmp(type, "identifier") == 0) {
        uint32_t start_byte = ts_node_start_byte(node);
        uint32_t end_byte = ts_node_end_byte(node);
        uint32_t length = end_byte - start_byte;

        char node_text[256];
        if (length < sizeof(node_text)) {
            strncpy(node_text, source_code + start_byte, length);
            node_text[length] = '\0';

            for (int i = 0; i < num_rules; i++) {
                if (strcmp(node_text, rules[i].identifier) == 0) {
                    TSPoint point = ts_node_start_point(node);
                    printf("[%s RISK] Line %u: Found API call '%s'\n", 
                           rules[i].risk, point.row + 1, node_text);
                    printf("  Details: %s\n", rules[i].message);
                    printf("  Suggested Replacement: %s\n\n", rules[i].replacement);
                }
            }
        }
    }

    uint32_t child_count = ts_node_child_count(node);
    for (uint32_t i = 0; i < child_count; i++) {
        traverse_ast(ts_node_child(node, i), source_code);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <c_source_file>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("Failed to open source file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *source_code = malloc(file_size + 1);
    if (fread(source_code, 1, file_size, file) != (size_t)file_size) {
        fprintf(stderr, "Warning: Did not read full file content.\n");
    }
    fclose(file);
    source_code[file_size] = '\0';

    clock_t start_time = clock();

    TSParser *parser = ts_parser_new();
    ts_parser_set_language(parser, tree_sitter_c());

    TSTree *tree = ts_parser_parse_string(parser, NULL, source_code, file_size);
    TSNode root_node = ts_tree_root_node(tree);

    printf("==================================================\n");
    printf(" AST QUANTUM RISK SCAN REPORT: %s\n", argv[1]);
    printf("==================================================\n\n");

    traverse_ast(root_node, source_code);

    clock_t end_time = clock();
    double elapsed_sec = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    printf("--------------------------------------------------\n");
    printf("Scan Completed in: %.4f seconds\n", elapsed_sec);

    ts_tree_delete(tree);
    ts_parser_delete(parser);
    free(source_code);

    return 0;
}
