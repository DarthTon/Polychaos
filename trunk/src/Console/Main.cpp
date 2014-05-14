#include "../Polychaos/PEMutator.h"

#include <iostream>

using namespace mut;

void usage()
{
    std::cout << "Usage: ZergConsole.exe <path_to_image> [output_path]\r\n"
              << "       path_to_image - path to the target PE image file\r\n"
              << "       output_path - resulting file, optional\r\n\r\n";
}

int main( int argc, char* argv[] )
{
    if (argc < 2)
    {
        usage();
        return 2;
    }

    try
    {
        PEMutator mutant( new MutationImpl() );

        auto path = argv[1];
        auto out = mutant.Mutate( path, argc > 2 ? argv[2] : "" );

        std::cout << "Successfully mutated. Result saved in '" << out << "'\r\n";
    }
    catch (std::exception& e)
    {
        std::cout << "Exception!\r\n" << e.what() << std::endl;
        return 1;
    }

    return 0;
}