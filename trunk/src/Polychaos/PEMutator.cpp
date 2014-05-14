#include "PEMutator.h"

#include <fstream>
#include <cassert>
#include <algorithm>

namespace mut
{

PEMutator::PEMutator( MutationImpl* pImpl )
    : _mutator( pImpl )
{
}


PEMutator::~PEMutator()
{
}

/// <summary>
/// Mutate executable
/// </summary>
/// <param name="filePath">Executable path</param>
/// <param name="newPath">Output file</param>
/// <returns>Output file path</returns>
std::string PEMutator::Mutate( const std::string& filePath, std::string newPath /*= "" */ )
{
    std::ifstream file( filePath, std::ios::binary | std::ios::in );
    _image.reset( new pe_bliss::pe_base( pe_bliss::pe_factory::create_pe( file ) ) );

    auto& secRef = _image->section_from_rva( _image->get_ep() );
    auto oldText = secRef;
    auto newText = secRef;

    size_t ep = _image->get_ep() - oldText.get_virtual_address();
    uint8_t* obuf = nullptr;

    auto& lastSec = _image->get_image_sections().back();

    // Set new section VA
    newText.set_virtual_address( lastSec.get_virtual_address() + 
                                 pe_bliss::pe_utils::align_up( lastSec.get_virtual_size(), _image->get_section_alignment() ) );

    // Mutate code section
    auto delta = newText.get_virtual_address() - secRef.get_virtual_address();
    auto sz = _mutator.Mutate( (uint8_t*)secRef.get_raw_data().c_str(),
                               oldText.get_virtual_size(),
                               ep, delta,
                               _image->get_image_base_32() + oldText.get_virtual_address(),
                               obuf );

    // Update old code
    newText.set_raw_data( std::string( obuf, obuf + sz ) );
    secRef.set_name( ".pdata" );

    _image->add_section( newText );
    _image->set_base_of_code( newText.get_virtual_address() );
    _image->set_ep( ep + oldText.get_virtual_address() + delta );

    // Perform PE fixups
    FixExport( oldText, newText );
    FixRelocs( oldText, newText );
    FixSafeSEH( oldText, newText );
    FixTLS( oldText, newText );

    // Build new name
    if (newPath.empty())
    {
        auto pt = filePath.rfind( '.' );
        if (pt != filePath.npos)
        {
            auto ext = filePath.substr( pt + 1 );
            auto name = filePath.substr( 0, pt );
            newPath = name + "_Mutated." + ext;
        }
        else
        {
            newPath = filePath + "_Mutated";
        }
    }

    std::ofstream new_file( newPath, std::ios::binary );
    if (!new_file.is_open())
        throw std::runtime_error( "Couldn't create output file: " + newPath );

    pe_bliss::rebuild_pe( *_image, new_file );

    return newPath;
}

/// <summary>
/// Fix relocations
/// </summary>
/// <param name="oldText">Original .text section</param>
/// <param name="newText">New .text section</param>
void PEMutator::FixRelocs( const pe_bliss::section& oldText, const pe_bliss::section& newText )
{
    // No relocations
    if (!_image->has_reloc())
        return;

    auto delta = newText.get_virtual_address() - oldText.get_virtual_address();
    auto relocs = pe_bliss::get_relocations( *_image );
    std::vector<std::pair<uint32_t, uint16_t>> tmpRelocs;

    for (size_t i = 0; i < relocs.size(); )
    {
        // Collect information about new relocation addresses
        if (relocs[i].get_rva() >= oldText.get_virtual_address() &&
             relocs[i].get_rva() < oldText.get_virtual_address() + oldText.get_virtual_size())
        {
            auto recBaseRVA = relocs[i].get_rva() - oldText.get_virtual_address();

            for (auto& rel : relocs[i].get_relocations())
            {
                auto pData = _mutator.GetIdataByRVA( rel.get_rva() + recBaseRVA );
                if (pData)
                    tmpRelocs.push_back( std::make_pair( rel.get_rva() - (pData->old_rva - recBaseRVA) + pData->new_rva, rel.get_type() ) );
               /* else
                    assert( false && "Invalid relocation RVA" );*/
            }

            relocs.erase( relocs.begin() + i );
        }
        else
            i++;
    }

    std::sort( tmpRelocs.begin(), tmpRelocs.end() );

    // Make new relocation table
    for (auto& rel : tmpRelocs)
    {
        auto page = rel.first >> 12;
        if (relocs.empty() || relocs.back().get_rva() != newText.get_virtual_address() + (page << 12))
        {
            relocs.push_back( pe_bliss::relocation_table() );
            relocs.back().set_rva( newText.get_virtual_address() + (page << 12) );
        }

        relocs.back().add_relocation( pe_bliss::relocation_entry( rel.first & 0xFFF, rel.second ) );
    }

    pe_bliss::rebuild_relocations( *_image, relocs, _image->section_from_directory( pe_bliss::pe_win::image_directory_entry_basereloc ) );
}

/// <summary>
/// Fix export section
/// </summary>
/// <param name="oldText">Original .text section</param>
/// <param name="newText">New .text section</param>
void PEMutator::FixExport( const pe_bliss::section& oldText, const pe_bliss::section& newText )
{
    // No exports
    if (!_image->has_exports())
        return;

    pe_bliss::export_info info;
    auto delta = newText.get_virtual_address() - oldText.get_virtual_address();
    auto exports = pe_bliss::get_exported_functions( *_image, info );

    for (auto& exp : exports)
    {
        if (exp.is_forwarded())
            continue;

        // Function inside old .text section
        if (exp.get_rva() >= oldText.get_virtual_address() && exp.get_rva() <= oldText.get_virtual_address() + oldText.get_virtual_size())
        {
            auto rva = exp.get_rva() - oldText.get_virtual_address();
            auto pData = _mutator.GetIdataByRVA( rva );
            if (pData)
                exp.set_rva( pData->new_rva + newText.get_virtual_address() );
            else
                assert( false && "Invalid export pointer" );
        }
    }

    pe_bliss::rebuild_exports( *_image, info, exports, _image->section_from_directory( pe_bliss::pe_win::image_directory_entry_export ) );
}

/// <summary>
/// Fix SAFESEH table
/// </summary>
/// <param name="oldText">Original .text section</param>
/// <param name="newText">New .text section</param>
void PEMutator::FixSafeSEH( const pe_bliss::section& oldText, const pe_bliss::section& newText )
{
    if (!_image->has_config())
        return;

    auto cfg = pe_bliss::get_image_config( *_image );
    auto& handlers = cfg.get_se_handler_rvas();

    for (size_t i = 0; i < handlers.size(); i++)
    {
        // Handler inside old section
        if (handlers[i] >= oldText.get_virtual_address() &&
             handlers[i] <= oldText.get_virtual_address() + oldText.get_virtual_size())
        {
            auto rva = handlers[i] - oldText.get_virtual_address();
            auto pData = _mutator.GetIdataByRVA( rva );
            if (pData)
                handlers[i] = pData->new_rva + newText.get_virtual_address();
            else
                assert( false && "Invalid handler" );
        }
    }

    auto pSectionData = _image->section_data_from_va( cfg.get_se_handler_table_va() );
    memcpy( pSectionData, &handlers[0], handlers.size() * sizeof(handlers[0]) );
}

/// <summary>
/// Fixes TLS callbacks
/// </summary>
/// <param name="oldText">Original .text section</param>
/// <param name="newText">New .text section</param>
void PEMutator::FixTLS( const pe_bliss::section& oldText, const pe_bliss::section& newText )
{
    if (!_image->has_tls())
        return;

    auto tls = pe_bliss::get_tls_info( *_image );
    if (tls.get_callbacks_rva() == 0)
        return;

    auto pSectionData = _image->section_data_from_rva( tls.get_callbacks_rva() );
    for (uint32_t* pCallback = (uint32_t*)pSectionData; *pCallback; pCallback++)
    {
        auto ptr = *pCallback - _image->get_image_base_32();

        // Callback belongs to old .text section
        if (ptr >= oldText.get_virtual_address() &&
            ptr <= oldText.get_virtual_address() + oldText.get_virtual_size())
        {
            // New address
            auto pData = _mutator.GetIdataByRVA( ptr - oldText.get_virtual_address() );
            if (pData)
                *pCallback = pData->new_rva + newText.get_virtual_address() + _image->get_image_base_32();
            else
                assert( false && "Invalid TLS callback" );
        }
    }
}

}