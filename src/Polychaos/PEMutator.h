#pragma once

#include "MutationEngine.h"
#include "../../contrib/portable-executable-library/pe_lib/pe_bliss.h"

namespace mut
{
    class PEMutator
    {
    public:
        PEMutator( MutationImpl* pImpl );
        ~PEMutator();

        /// <summary>
        /// Mutate executable
        /// </summary>
        /// <param name="filePath">Executable path</param>
        /// <param name="newPath">Output file</param>
        /// <returns>Output file path</returns>
        std::string Mutate( const std::string& filePath, std::string newPath = "" );

    private:
        /// <summary>
        /// Fix relocations
        /// </summary>
        /// <param name="oldText">Original .text section</param>
        /// <param name="newText">New .text section</param>
        void FixRelocs( const pe_bliss::section& oldText, const pe_bliss::section& newText );

        /// <summary>
        /// Fix export section
        /// </summary>
        /// <param name="oldText">Original .text section</param>
        /// <param name="newText">New .text section</param>
        void FixExport( const pe_bliss::section& oldText, const pe_bliss::section& newText );

        /// <summary>
        /// Fix SAFESEH table
        /// </summary>
        /// <param name="oldText">Original .text section</param>
        /// <param name="newText">New .text section</param>
        void FixSafeSEH( const pe_bliss::section& oldText, const pe_bliss::section& newText );

        /// <summary>
        /// Fixes TLS callbacks
        /// </summary>
        /// <param name="oldText">Original .text section</param>
        /// <param name="newText">New .text section</param>
        void FixTLS( const pe_bliss::section& oldText, const pe_bliss::section& newText );

    private:
        std::unique_ptr<pe_bliss::pe_base> _image;
        MutationEngine _mutator;
    };

}