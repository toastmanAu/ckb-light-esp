idf_component_register(
    SRCS "src/ckb_secio.c" "src/ckb_yamux.c" "src/ckb_molecule.c"
    INCLUDE_DIRS "include"
    REQUIRES ckb_core mbedtls
)
