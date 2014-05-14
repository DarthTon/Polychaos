#pragma once
#include <ostream>

namespace pe_bliss
{
class pe_base;
//Rebuilds PE image, writes resulting image to ostream "out". If strip_dos_header == true, DOS header will be stripped a little
//If change_size_of_headers == true, SizeOfHeaders will be recalculated automatically
//If save_bound_import == true, existing bound import directory will be saved correctly (because some compilers and bind.exe put it to PE headers)
void rebuild_pe(pe_base& pe, std::ostream& out, bool strip_dos_header = false, bool change_size_of_headers = true, bool save_bound_import = true);
}
