"""Expose Open5GS runtime NF UUID to a host-side Stage 39 witness.

This does not modify NRF registration/discovery behavior.  It only writes the
locally generated runtime instance UUID to a file inside the NF container so a
host-level witness can read it without querying NRF.
"""
from pathlib import Path

path = Path("/src/open5gs/lib/sbi/context.c")
text = path.read_text()

include_needle = '#include "ogs-sbi.h"\n'
include_insert = include_needle + '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n'
if "STAGE39_WITNESS_DIR" not in text:
    if include_needle not in text:
        raise SystemExit("context include marker not found")
    text = text.replace(include_needle, include_insert, 1)

needle = "    ogs_sbi_nf_instance_set_type(self.nf_instance, nf_type);\n"
instrument = needle + r'''
    {
        const char *stage39_dir = getenv("STAGE39_WITNESS_DIR");
        if (stage39_dir && *stage39_dir) {
            char witness_path[512];
            FILE *witness_fp = NULL;
            snprintf(witness_path, sizeof(witness_path),
                    "%s/runtime.tsv", stage39_dir);
            witness_fp = fopen(witness_path, "w");
            if (witness_fp) {
                fprintf(witness_fp, "%ld\t%d\t%s\n",
                        (long)getpid(), (int)nf_type, nf_instance_id);
                fclose(witness_fp);
            } else {
                ogs_error("STAGE39: cannot write runtime witness [%s]",
                        witness_path);
            }
        }
    }
'''
if "STAGE39: cannot write runtime witness" not in text:
    if needle not in text:
        raise SystemExit("NF instance marker not found")
    text = text.replace(needle, instrument, 1)

path.write_text(text)
print("STAGE39_SBI_CONTEXT_PATCH_OK")
