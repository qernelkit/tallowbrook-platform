#include "archive/archive_writer.hh"
#include "test.hh"

using namespace vaultarc;

TEST(container_round_trips_the_header) {
    ArchiveHeader header;
    header.archive_id = "arc-2026-04417";
    header.format = Format::kFormat2;
    header.original_size = 1234567;
    header.chunk_count = 42;

    Bytes payload(64, 0x11);
    Bytes manifest(16, 0x22);
    Bytes container = write_container(header, payload, manifest);

    ArchiveHeader parsed;
    CHECK(read_header(container, parsed));
    CHECK(parsed.format == Format::kFormat2);
    CHECK(parsed.original_size == 1234567);
    CHECK(parsed.chunk_count == 42);
}

TEST(container_rejects_foreign_bytes) {
    Bytes junk(32, 0x00);
    ArchiveHeader parsed;
    CHECK(!read_header(junk, parsed));
}
